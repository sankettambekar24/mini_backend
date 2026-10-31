import base64
import json
import uuid
from contextlib import contextmanager
from datetime import timedelta
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.devices.models import Device, DeviceStatus
from apps.hardware_auth.models import AuthAttempt, AuthAttemptCapability, AttemptStatus
from apps.offline_policies.models import (
    OfflinePolicy,
    OfflinePolicyFileScope,
    OfflinePolicyScope,
    OfflinePolicyStatus,
)
from apps.offline_policies.services import (
    OfflinePolicyError,
    POLICY_ALGORITHM,
    POLICY_TYP,
    sign_policy,
    verify_policy,
)
from apps.storage.models import StoredFileMetadata


User = get_user_model()
TEST_KID = "offline-test-key"


@contextmanager
def signing_enabled_for_test():
    """Lift the code-owned gate only inside isolated signer unit tests."""
    with override_settings(OFFLINE_POLICY_ISSUANCE_ENABLED=True):
        with patch("apps.offline_policies.services.UNMET_ISSUANCE_PREREQUISITES", ()):
            yield


class OfflinePolicyServiceTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(username="policy_user", password="GoodPassword!123")
        cls.other_user = User.objects.create_user(username="policy_other", password="GoodPassword!123")
        cls.device = Device.objects.create(
            device_label="Policy device",
            device_public_id="policy-device-public-id",
            owner_user=cls.user,
            status=DeviceStatus.ACTIVE,
        )
        cls.file = StoredFileMetadata.objects.create(
            owner_user=cls.user,
            device=cls.device,
            display_name="one.txt",
        )
        cls.private_key_obj = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.private_key = cls.private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")
        cls.public_key = cls.private_key_obj.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def setUp(self):
        self.key_settings = override_settings(
            OFFLINE_POLICY_SIGNING_KEY_ID=TEST_KID,
            OFFLINE_POLICY_SIGNING_PRIVATE_KEY=self.private_key,
            OFFLINE_POLICY_VERIFYING_KEYS_JSON=json.dumps({TEST_KID: self.public_key}),
            OFFLINE_POLICY_ISSUANCE_ENABLED=False,
            OFFLINE_POLICY_MAX_SECONDS=86400,
            OFFLINE_POLICY_ISSUER="test-issuer",
            OFFLINE_POLICY_AUDIENCE="test-client",
        )
        self.key_settings.enable()

    def tearDown(self):
        self.key_settings.disable()

    def create_signed_policy(self, *, status=OfflinePolicyStatus.ISSUED, issued_at=None, expires_at=None):
        issued_at = issued_at or timezone.now()
        expires_at = expires_at or issued_at + timedelta(minutes=10)
        policy = OfflinePolicy.objects.create(
            policy_id=uuid.uuid4(),
            policy_version=1,
            schema_version=1,
            user=self.user,
            device=self.device,
            device_key_id="test-device-key",
            status=OfflinePolicyStatus.PREPARED,
            max_offline_seconds=3600,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        OfflinePolicyFileScope.objects.create(policy=policy, file=self.file, scope=OfflinePolicyScope.READ)
        with signing_enabled_for_test():
            signed, key_id = sign_policy(policy)
        policy.status = status
        policy.signing_key_id = key_id
        policy.signed_policy = signed
        policy.save(update_fields=["status", "signing_key_id", "signed_policy", "updated_at"])
        return policy, signed

    def assert_policy_error(self, code, **kwargs):
        with self.assertRaises(OfflinePolicyError) as context:
            verify_policy(**kwargs)
        self.assertEqual(context.exception.code, code)

    def test_valid_signature_is_verified_against_policy_record_and_scope(self):
        policy, token = self.create_signed_policy()
        verified = verify_policy(
            token,
            expected_user_id=self.user.id,
            expected_device_id=self.device.id,
        )
        self.assertEqual(verified.id, policy.id)

    def test_modified_payload_and_invalid_signature_are_rejected(self):
        _policy, token = self.create_signed_policy()
        parts = token.split(".")
        payload = jwt.decode(token, options={"verify_signature": False})
        payload["device_id"] = str(uuid.uuid4())
        parts[1] = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ).rstrip(b"=").decode("ascii")
        self.assert_policy_error(
            "INVALID_POLICY_SIGNATURE",
            token=".".join(parts),
            expected_user_id=self.user.id,
            expected_device_id=self.device.id,
        )

        parts = token.split(".")
        parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
        self.assert_policy_error(
            "INVALID_POLICY_SIGNATURE",
            token=".".join(parts),
            expected_user_id=self.user.id,
            expected_device_id=self.device.id,
        )

    def test_malformed_policy_and_duplicate_json_keys_are_rejected(self):
        self.assert_policy_error(
            "MALFORMED_POLICY",
            token="not.a.valid.policy",
            expected_user_id=self.user.id,
            expected_device_id=self.device.id,
        )
        duplicate_header = base64.urlsafe_b64encode(b'{"alg":"RS256","alg":"none","kid":"x","typ":"x"}').rstrip(b"=").decode()
        self.assert_policy_error(
            "MALFORMED_POLICY",
            token=f"{duplicate_header}.e30.YWJj",
            expected_user_id=self.user.id,
            expected_device_id=self.device.id,
        )

    def test_expired_policy_is_rejected_and_lifecycle_is_marked_expired(self):
        now = timezone.now()
        policy, token = self.create_signed_policy(
            issued_at=now - timedelta(hours=1),
            expires_at=now - timedelta(minutes=1),
        )
        self.assert_policy_error(
            "POLICY_EXPIRED",
            token=token,
            expected_user_id=self.user.id,
            expected_device_id=self.device.id,
            now=now,
        )
        policy.refresh_from_db()
        self.assertEqual(policy.status, OfflinePolicyStatus.EXPIRED)

    def test_revoked_policy_is_rejected(self):
        policy, token = self.create_signed_policy(status=OfflinePolicyStatus.REVOKED)
        policy.revoked_at = timezone.now()
        policy.revoked_by = self.user
        policy.save(update_fields=["revoked_at", "revoked_by", "updated_at"])
        self.assert_policy_error(
            "POLICY_REVOKED",
            token=token,
            expected_user_id=self.user.id,
            expected_device_id=self.device.id,
        )

    def test_wrong_user_and_wrong_device_are_rejected(self):
        _policy, token = self.create_signed_policy()
        self.assert_policy_error(
            "POLICY_USER_MISMATCH",
            token=token,
            expected_user_id=self.other_user.id,
            expected_device_id=self.device.id,
        )
        self.assert_policy_error(
            "POLICY_DEVICE_MISMATCH",
            token=token,
            expected_user_id=self.user.id,
            expected_device_id=uuid.uuid4(),
        )

    def test_unsupported_schema_version_is_rejected(self):
        _policy, token = self.create_signed_policy()
        claims = jwt.decode(token, options={"verify_signature": False})
        claims["schema"] = "hsss.offline-policy.v2"
        claims["schema_version"] = 2
        unsupported = jwt.encode(
            claims,
            self.private_key,
            algorithm=POLICY_ALGORITHM,
            headers={"typ": POLICY_TYP, "kid": TEST_KID},
        )
        self.assert_policy_error(
            "UNSUPPORTED_POLICY_VERSION",
            token=unsupported,
            expected_user_id=self.user.id,
            expected_device_id=self.device.id,
        )

    def test_missing_signing_configuration_fails_without_fallback_key(self):
        policy = OfflinePolicy.objects.create(
            user=self.user,
            device=self.device,
            device_key_id="test-device-key",
            status=OfflinePolicyStatus.PREPARED,
            max_offline_seconds=3600,
            issued_at=timezone.now(),
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        OfflinePolicyFileScope.objects.create(policy=policy, file=self.file, scope=OfflinePolicyScope.READ)
        with signing_enabled_for_test():
            with override_settings(OFFLINE_POLICY_SIGNING_KEY_ID="", OFFLINE_POLICY_SIGNING_PRIVATE_KEY=""):
                with self.assertRaises(OfflinePolicyError) as context:
                    sign_policy(policy)
        self.assertEqual(context.exception.code, "OFFLINE_POLICY_SIGNING_CONFIGURATION_MISSING")

    @override_settings(OFFLINE_POLICY_ISSUANCE_ENABLED=True)
    def test_internal_signer_cannot_bypass_unmet_prerequisites_or_direct_model_creation(self):
        policy = OfflinePolicy.objects.create(
            user=self.user,
            device=self.device,
            device_key_id="test-device-key",
            status=OfflinePolicyStatus.PREPARED,
            max_offline_seconds=3600,
            issued_at=timezone.now(),
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        OfflinePolicyFileScope.objects.create(policy=policy, file=self.file, scope=OfflinePolicyScope.READ)

        with self.assertRaises(OfflinePolicyError) as context:
            sign_policy(policy)

        self.assertEqual(context.exception.code, "OFFLINE_POLICY_ISSUANCE_DISABLED")
        policy.refresh_from_db()
        self.assertEqual(policy.status, OfflinePolicyStatus.PREPARED)
        self.assertEqual(policy.signed_policy, "")

    def test_missing_verification_configuration_fails_closed(self):
        _policy, token = self.create_signed_policy()
        with override_settings(OFFLINE_POLICY_VERIFYING_KEYS_JSON=""):
            self.assert_policy_error(
                "OFFLINE_POLICY_VERIFICATION_CONFIGURATION_MISSING",
                token=token,
                expected_user_id=self.user.id,
                expected_device_id=self.device.id,
            )

    def test_invalid_verification_key_configuration_is_rejected(self):
        _policy, token = self.create_signed_policy()
        for key_material in ("not a public key", self.private_key):
            with self.subTest(key_material="private" if key_material == self.private_key else "malformed"):
                with override_settings(OFFLINE_POLICY_VERIFYING_KEYS_JSON=json.dumps({TEST_KID: key_material})):
                    self.assert_policy_error(
                        "OFFLINE_POLICY_VERIFICATION_CONFIGURATION_INVALID",
                        token=token,
                        expected_user_id=self.user.id,
                        expected_device_id=self.device.id,
                    )


class OfflinePolicyAPITests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="preauth_user", password="GoodPassword!123")
        self.other = User.objects.create_user(username="preauth_other", password="GoodPassword!123")
        self.device = Device.objects.create(
            device_label="Preauth device",
            device_public_id="preauth-device-public-id",
            owner_user=self.user,
            status=DeviceStatus.ACTIVE,
        )
        self.client = APIClient()

    def test_preauth_returns_attempt_capability_but_no_normal_jwt(self):
        response = self.client.post(
            "/api/v1/auth/preauth/",
            {"username": "preauth_user", "password": "GoodPassword!123", "device_id": str(self.device.id)},
            format="json",
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertNotIn("access", response.data)
        self.assertNotIn("refresh", response.data)
        self.assertNotIn("token", response.data)
        attempt_id = response.data["attempt"]["id"]
        capability = response.data["attempt_capability"]
        stored = AuthAttemptCapability.objects.get(attempt_id=attempt_id)
        self.assertNotEqual(stored.token_digest, capability)
        self.assertEqual(stored.expires_at, AuthAttempt.objects.get(id=attempt_id).expires_at)

        attempt_response = self.client.get(
            f"/api/v1/auth-attempts/{attempt_id}/",
            HTTP_X_AUTH_ATTEMPT_CAPABILITY=capability,
        )
        self.assertEqual(attempt_response.status_code, 200, attempt_response.data)
        ordinary_api = self.client.get(
            "/api/v1/auth/me/",
            HTTP_X_AUTH_ATTEMPT_CAPABILITY=capability,
        )
        self.assertEqual(ordinary_api.status_code, 401)
        for path in ("/api/v1/devices/", "/api/v1/offline-policies/", "/api/v1/auth-attempts/"):
            with self.subTest(path=path):
                response = self.client.get(path, HTTP_X_AUTH_ATTEMPT_CAPABILITY=capability)
                self.assertEqual(response.status_code, 401)
        complete_response = self.client.post(
            f"/api/v1/auth-attempts/{attempt_id}/complete/",
            {"device_id": str(self.device.id)},
            format="json",
            HTTP_X_AUTH_ATTEMPT_CAPABILITY=capability,
        )
        self.assertEqual(complete_response.status_code, 401)
        self.assertEqual(AuthAttempt.objects.get(id=attempt_id).status, AttemptStatus.PENDING)

    def test_attempt_capability_cannot_be_reused_for_another_attempt(self):
        response = self.client.post(
            "/api/v1/auth/preauth/",
            {"username": "preauth_user", "password": "GoodPassword!123", "device_id": str(self.device.id)},
            format="json",
        )
        self.assertEqual(response.status_code, 201)
        attempt = AuthAttempt.objects.create(
            user=self.user,
            device=self.device,
            status=AttemptStatus.PENDING,
            required_factors=["PIN", "FACE", "FINGERPRINT"],
            expires_at=timezone.now() + timedelta(minutes=5),
        )
        replay = self.client.get(
            f"/api/v1/auth-attempts/{attempt.id}/",
            HTTP_X_AUTH_ATTEMPT_CAPABILITY=response.data["attempt_capability"],
        )
        self.assertEqual(replay.status_code, 401)

    def test_attempt_capability_expiry_and_terminal_state_are_enforced(self):
        response = self.client.post(
            "/api/v1/auth/preauth/",
            {"username": "preauth_user", "password": "GoodPassword!123", "device_id": str(self.device.id)},
            format="json",
        )
        self.assertEqual(response.status_code, 201)
        attempt_id = response.data["attempt"]["id"]
        capability = response.data["attempt_capability"]
        stored = AuthAttemptCapability.objects.get(attempt_id=attempt_id)

        stored.expires_at = timezone.now() - timedelta(seconds=1)
        stored.save(update_fields=["expires_at"])
        expired = self.client.get(
            f"/api/v1/auth-attempts/{attempt_id}/",
            HTTP_X_AUTH_ATTEMPT_CAPABILITY=capability,
        )
        self.assertEqual(expired.status_code, 401)

        stored.expires_at = timezone.now() + timedelta(minutes=5)
        stored.save(update_fields=["expires_at"])
        attempt = AuthAttempt.objects.get(id=attempt_id)
        attempt.status = AttemptStatus.CANCELLED
        attempt.save(update_fields=["status"])
        terminal = self.client.get(
            f"/api/v1/auth-attempts/{attempt_id}/",
            HTTP_X_AUTH_ATTEMPT_CAPABILITY=capability,
        )
        self.assertEqual(terminal.status_code, 401)

    @override_settings(OFFLINE_POLICY_ISSUANCE_ENABLED=True)
    def test_policy_issuance_remains_disabled_even_when_config_switch_is_true(self):
        self.client.force_authenticate(self.user)
        response = self.client.post(
            "/api/v1/offline-policies/",
            {"device_id": str(self.device.id), "files": []},
            format="json",
        )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.data["error"]["code"], "OFFLINE_POLICY_ISSUANCE_DISABLED")
        self.assertEqual(OfflinePolicy.objects.count(), 0)

    def test_non_owner_cannot_revoke_policy(self):
        policy = OfflinePolicy.objects.create(
            user=self.user,
            device=self.device,
            status=OfflinePolicyStatus.ISSUED,
            max_offline_seconds=300,
            issued_at=timezone.now(),
            expires_at=timezone.now() + timedelta(minutes=5),
        )
        self.client.force_authenticate(self.other)
        response = self.client.post(f"/api/v1/offline-policies/{policy.id}/revoke/", {}, format="json")
        self.assertEqual(response.status_code, 404)
        policy.refresh_from_db()
        self.assertEqual(policy.status, OfflinePolicyStatus.ISSUED)

    def test_strict_revoke_audit_failure_rolls_back_policy_state(self):
        policy = OfflinePolicy.objects.create(
            user=self.user,
            device=self.device,
            status=OfflinePolicyStatus.ISSUED,
            max_offline_seconds=300,
            issued_at=timezone.now(),
            expires_at=timezone.now() + timedelta(minutes=5),
        )
        self.client.force_authenticate(self.user)
        self.client.raise_request_exception = False
        with patch("apps.offline_policies.services.record_audit_event", side_effect=RuntimeError("audit unavailable")):
            response = self.client.post(f"/api/v1/offline-policies/{policy.id}/revoke/", {}, format="json")
        self.assertEqual(response.status_code, 500)
        policy.refresh_from_db()
        self.assertEqual(policy.status, OfflinePolicyStatus.ISSUED)
        self.assertIsNone(policy.revoked_at)
