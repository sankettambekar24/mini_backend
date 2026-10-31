"""
Phase 2 Test Suite: Hybrid Secure Storage System.

Covers all required Phase 2 security release gates:
1. Admin Bootstrap:
   - Success path, single-admin rejection, weak password rejection, no credential leaks in CLI output.
2. Brute-Force & Throttling:
   - Throttling triggered on excessive attempts, audit lockout event generated.
   - Username-enumeration resistance: identical responses for nonexistent vs wrong password.
3. Token Lifecycle & Immediate Invalidation:
   - Access token immediately revoked upon password change (token_version increment).
   - Access token immediately revoked upon role change (role/version mismatch).
   - Access token immediately rejected upon account deactivation (user_inactive).
   - Refresh token blacklisting and logout revocation.
4. Privilege Escalation Defense:
   - Non-admin blocked from role modifications, disable endpoints, and user creation.
5. Audit Integrity & Secret Sanitization:
   - Strict stripping of passwords, tokens, PINs, and biometrics from metadata.
   - HTTP method restrictions: audit logs are strictly append-only (POST/PUT/DELETE rejected).
"""

import io
import uuid
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import override_settings
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.tokens import AccessToken

from apps.accounts.models import UserRole
from apps.audit.models import AuditEvent, AuditEventType
from apps.audit.services import record_audit_event

User = get_user_model()


def create_user(username=None, password="SecurePass!99", role=UserRole.USER, is_active=True):
    username = username or f"user_{uuid.uuid4().hex[:8]}"
    user = User.objects.create_user(username=username, password=password)
    user.is_active = is_active
    if role == UserRole.ADMIN:
        user.role = UserRole.ADMIN
        user.is_staff = True
        user.is_superuser = True
    user.save()
    return user


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    refresh["token_version"] = user.token_version
    refresh["role"] = user.role
    refresh["username"] = user.username
    return str(refresh.access_token), str(refresh)


# ===========================================================================
# 1. Admin Bootstrap Tests
# ===========================================================================

class AdminBootstrapTests(APITestCase):
    def setUp(self):
        cache.clear()
        # Ensure no existing admin before bootstrap test
        User.objects.filter(role=UserRole.ADMIN).delete()

    def test_bootstrap_admin_success(self):
        out = io.StringIO()
        call_command(
            "bootstrap_admin",
            username="initial_admin",
            password="StrongAdminPassword!99",
            no_input=True,
            stdout=out,
        )
        self.assertIn("Successfully bootstrapped designated administrator", out.getvalue())

        admin = User.objects.get(username="initial_admin")
        self.assertEqual(admin.role, UserRole.ADMIN)
        self.assertTrue(admin.is_staff)
        self.assertTrue(admin.is_superuser)

        # Verify audit record
        audit = AuditEvent.objects.filter(event_type="ADMIN_BOOTSTRAP", safe_metadata__username="initial_admin")
        self.assertTrue(audit.exists())

    def test_bootstrap_admin_rejected_when_admin_exists(self):
        create_user(username="existing_admin", role=UserRole.ADMIN)
        out = io.StringIO()
        with self.assertRaises(CommandError) as ctx:
            call_command(
                "bootstrap_admin",
                username="second_admin",
                password="StrongAdminPassword!99",
                no_input=True,
                stdout=out,
            )
        self.assertIn("already exists", str(ctx.exception))
        self.assertFalse(User.objects.filter(username="second_admin").exists())

    def test_bootstrap_admin_weak_password_rejected(self):
        out = io.StringIO()
        with self.assertRaises(CommandError) as ctx:
            call_command(
                "bootstrap_admin",
                username="bad_pass_admin",
                password="short",
                no_input=True,
                stdout=out,
            )
        self.assertIn("Password does not meet security requirements", str(ctx.exception))
        self.assertFalse(User.objects.filter(username="bad_pass_admin").exists())

    def test_bootstrap_admin_rejects_numeric_only_and_username_similar_passwords(self):
        for username, password in (
            ("numeric_bootstrap", "1234567890"),
            ("similar_bootstrap", "similar_bootstrap!123"),
        ):
            with self.subTest(username=username):
                with self.assertRaises(CommandError):
                    call_command("bootstrap_admin", username=username, password=password, no_input=True)

    def test_bootstrap_admin_password_not_leaked_in_output(self):
        out = io.StringIO()
        err = io.StringIO()
        password = "SecretPassword!12345"
        call_command(
            "bootstrap_admin",
            username="leak_check_admin",
            password=password,
            no_input=True,
            stdout=out,
            stderr=err,
        )
        self.assertNotIn(password, out.getvalue())
        self.assertNotIn(password, err.getvalue())


# ===========================================================================
# 2. Login Throttling & Username Enumeration Resistance
# ===========================================================================

class LoginThrottlingAndEnumerationTests(APITestCase):
    login_url = "/api/v1/auth/token/"

    def setUp(self):
        cache.clear()
        self.user = create_user(username="throttle_target", password="TargetPassword!99")

    def test_username_enumeration_resistance(self):
        """
        Both a non-existent username and an existing user with incorrect password
        must return identical HTTP 401 responses, preventing username harvesting.
        """
        res_nonexistent = self.client.post(
            self.login_url,
            {"username": "non_existent_user_9999", "password": "AnyPassword!99"},
        )
        res_wrong_pass = self.client.post(
            self.login_url,
            {"username": "throttle_target", "password": "WrongPassword!99"},
        )

        self.assertEqual(res_nonexistent.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(res_wrong_pass.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(res_nonexistent.data["error"]["code"], res_wrong_pass.data["error"]["code"])

    def test_login_throttling_triggers_and_logs_lockout(self):
        """Excessive failed attempts exceed rate limit and trigger a lockout audit event."""
        cache.clear()
        # Default rate is 5/minute for auth_login_user
        for _ in range(5):
            self.client.post(
                self.login_url,
                {"username": "throttle_target", "password": "WrongPass!99"},
            )

        # 6th request must be throttled
        response = self.client.post(
            self.login_url,
            {"username": "throttle_target", "password": "WrongPass!99"},
        )
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertEqual(response.data["error"]["code"], "THROTTLED")

        # Verify lockout audit event was created
        lockout_audit = AuditEvent.objects.filter(
            event_type="LOGIN_LOCKED_OUT",
            safe_metadata__username="throttle_target",
        )
        self.assertTrue(lockout_audit.exists())
        self.assertIn("wait_seconds", lockout_audit.first().safe_metadata)


# ===========================================================================
# 3. Token Lifecycle & Immediate Invalidation
# ===========================================================================

class TokenLifecycleAndRevocationTests(APITestCase):
    me_url = "/api/v1/auth/me/"
    change_password_url = "/api/v1/auth/change-password/"
    refresh_url = "/api/v1/auth/token/refresh/"
    logout_url = "/api/v1/auth/logout/"

    def setUp(self):
        cache.clear()
        self.user = create_user(username="lifecycle_user", password="InitialPass!99")
        self.access, self.refresh = get_tokens_for_user(self.user)
        self.admin = create_user(username="lifecycle_admin", role=UserRole.ADMIN)
        self.admin_access, _ = get_tokens_for_user(self.admin)

    def test_access_token_invalidated_immediately_on_password_change(self):
        """
        After password change, user's token_version is incremented.
        The old access token must be immediately rejected on subsequent requests.
        """
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access}")

        # Access token works initially
        res1 = self.client.get(self.me_url)
        self.assertEqual(res1.status_code, status.HTTP_200_OK)

        # Change password
        res_change = self.client.post(
            self.change_password_url,
            {"current_password": "InitialPass!99", "new_password": "NewStrongPass!99"},
        )
        self.assertEqual(res_change.status_code, status.HTTP_200_OK)

        # Using the OLD access token must now fail with token_revoked
        res_old_token = self.client.get(self.me_url)
        self.assertEqual(res_old_token.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(res_old_token.data["error"]["code"], "TOKEN_REVOKED")

    def test_access_token_invalidated_immediately_on_role_change(self):
        """
        When an admin changes a user's role, the user's previous access tokens
        must be immediately rejected (role mismatch & version increment).
        """
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access}")
        res1 = self.client.get(self.me_url)
        self.assertEqual(res1.status_code, status.HTTP_200_OK)

        # Simulate a pre-existing second administrator, then demote it through
        # the audited API. New promotion is intentionally blocked by policy.
        self.user.role = UserRole.ADMIN
        self.user.is_staff = True
        self.user.is_superuser = True
        self.user.save(update_fields=["role", "is_staff", "is_superuser"])
        self.access, _ = get_tokens_for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_access}")
        url = f"/api/v1/admin/users/{self.user.id}/role/"
        res_role = self.client.post(url, {"role": "USER"}, format="json")
        self.assertEqual(res_role.status_code, status.HTTP_200_OK)

        # User's old access token with role=ADMIN must now be rejected.
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access}")
        res_revoked = self.client.get(self.me_url)
        self.assertEqual(res_revoked.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn(res_revoked.data["error"]["code"], ["TOKEN_REVOKED", "ROLE_CHANGED"])

    def test_admin_promotion_is_rejected_when_designated_admin_exists(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_access}")
        response = self.client.post(
            f"/api/v1/admin/users/{self.user.id}/role/", {"role": "ADMIN"}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.user.refresh_from_db()
        self.assertEqual(self.user.role, UserRole.USER)

    def test_access_token_rejected_immediately_on_account_deactivation(self):
        """Deactivating an account immediately stops existing access tokens from functioning."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access}")
        res1 = self.client.get(self.me_url)
        self.assertEqual(res1.status_code, status.HTTP_200_OK)

        # Admin deactivates account
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_access}")
        url = f"/api/v1/admin/users/{self.user.id}/disable/"
        res_disable = self.client.post(url)
        self.assertEqual(res_disable.status_code, status.HTTP_200_OK)

        # Old access token must be immediately rejected
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access}")
        res_revoked = self.client.get(self.me_url)
        self.assertEqual(res_revoked.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(res_revoked.data["error"]["code"], "USER_INACTIVE")

    def test_deactivated_user_cannot_refresh_token(self):
        """Deactivated user cannot use refresh token to acquire new access tokens."""
        self.user.is_active = False
        self.user.save()

        res = self.client.post(self.refresh_url, {"refresh": self.refresh})
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_access_tokens_require_role_and_version_claims(self):
        token = AccessToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {str(token)}")
        response = self.client.get(self.me_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data["error"]["code"], "INVALID_TOKEN_CLAIMS")

    def test_access_tokens_reject_malformed_or_stale_security_claims(self):
        cases = [
            ({"token_version": True, "role": UserRole.USER}, "INVALID_TOKEN_CLAIMS"),
            ({"token_version": "1", "role": UserRole.USER}, "INVALID_TOKEN_CLAIMS"),
            ({"token_version": self.user.token_version, "role": "ROOT"}, "INVALID_TOKEN_CLAIMS"),
            ({"token_version": 0, "role": UserRole.USER}, "INVALID_TOKEN_CLAIMS"),
            ({"token_version": self.user.token_version, "role": UserRole.ADMIN}, "ROLE_CHANGED"),
        ]
        for claims, expected_code in cases:
            with self.subTest(claims=claims):
                token = AccessToken.for_user(self.user)
                for key, value in claims.items():
                    token[key] = value
                self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {str(token)}")
                response = self.client.get(self.me_url)
                self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
                self.assertEqual(response.data["error"]["code"], expected_code)

    def test_old_refresh_token_is_rejected_after_password_change(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access}")
        response = self.client.post(
            self.change_password_url,
            {"current_password": "InitialPass!99", "new_password": "ChangedPassphrase!938"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        refresh_response = self.client.post(self.refresh_url, {"refresh": self.refresh})
        self.assertEqual(refresh_response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_refresh_rejects_malformed_claim_types(self):
        refresh = RefreshToken.for_user(self.user)
        refresh["token_version"] = True
        refresh["role"] = UserRole.USER
        response = self.client.post(self.refresh_url, {"refresh": str(refresh)})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_management_password_change_increments_token_version(self):
        from unittest.mock import patch
        from django.core.management import call_command

        old_access = self.access
        with patch("apps.accounts.management.commands.changepassword.getpass.getpass",
                   side_effect=["FreshUncommon!Password873", "FreshUncommon!Password873"]):
            call_command("changepassword", username=self.user.username, stdout=io.StringIO())
        self.user.refresh_from_db()
        self.assertEqual(self.user.token_version, 2)
        self.assertTrue(AuditEvent.objects.filter(
            event_type="PASSWORD_CHANGED", actor_user=self.user,
            safe_metadata__source="management_command",
        ).exists())
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {old_access}")
        response = self.client.get(self.me_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data["error"]["code"], "TOKEN_REVOKED")

    def test_logout_with_revoke_all_revokes_access_tokens(self):
        """Logout with revoke_all=True invalidates all access tokens for the account."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access}")
        res_logout = self.client.post(self.logout_url, {"refresh": self.refresh, "revoke_all": True})
        self.assertEqual(res_logout.status_code, status.HTTP_200_OK)

        # Access token must now be rejected
        res_check = self.client.get(self.me_url)
        self.assertEqual(res_check.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(res_check.data["error"]["code"], "TOKEN_REVOKED")

    def test_logout_without_revoke_all_only_revokes_refresh_token(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access}")
        response = self.client.post(self.logout_url, {"refresh": self.refresh})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(self.client.get(self.me_url).status_code, status.HTTP_200_OK)
        self.assertEqual(
            self.client.post(self.refresh_url, {"refresh": self.refresh}).status_code,
            status.HTTP_401_UNAUTHORIZED,
        )


# ===========================================================================
# 4. Privilege Escalation Defense Tests
# ===========================================================================

class PrivilegeEscalationDefenseTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.attacker = create_user(username="attacker_user", role=UserRole.USER)
        self.victim = create_user(username="victim_user", role=UserRole.USER)
        self.attacker_access, _ = get_tokens_for_user(self.attacker)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.attacker_access}")

    def test_normal_user_cannot_promote_self(self):
        url = f"/api/v1/admin/users/{self.attacker.id}/role/"
        res = self.client.post(url, {"role": "ADMIN"}, format="json")
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)
        self.attacker.refresh_from_db()
        self.assertEqual(self.attacker.role, UserRole.USER)

    def test_normal_user_cannot_disable_others(self):
        url = f"/api/v1/admin/users/{self.victim.id}/disable/"
        res = self.client.post(url)
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)
        self.victim.refresh_from_db()
        self.assertTrue(self.victim.is_active)

    def test_normal_user_cannot_create_admin_via_admin_api(self):
        url = "/api/v1/admin/users/"
        payload = {"username": "escalated_admin", "password": "StrongPassword!99", "role": "ADMIN"}
        res = self.client.post(url, payload, format="json")
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)


# ===========================================================================
# 5. Audit Integrity & Secret Redaction Tests
# ===========================================================================

class AuditIntegrityAndSanitizationTests(APITestCase):
    events_url = "/api/v1/audit/events/"

    def setUp(self):
        cache.clear()
        self.admin = create_user(username="sec_audit_admin", role=UserRole.ADMIN)
        self.admin_access, _ = get_tokens_for_user(self.admin)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_access}")

    def test_record_audit_event_sanitizes_forbidden_keys(self):
        """Even if code attempts to pass passwords/tokens in metadata, they are stripped."""
        dirty_metadata = {
            "username": "safe_name",
            "password": "plain_password_leak",
            "pin": "1234",
            "token": "secret_jwt",
            "biometric_encoding": [0.1, 0.2],
            "client_version": "2.0.0",
        }
        record_audit_event(
            event_type="TEST_DIRTY_LOG",
            result="SUCCESS",
            actor_user=self.admin,
            safe_metadata=dirty_metadata,
        )

        event = AuditEvent.objects.get(event_type="TEST_DIRTY_LOG")
        stored = event.safe_metadata
        self.assertIn("username", stored)
        self.assertIn("client_version", stored)
        self.assertNotIn("password", stored)
        self.assertNotIn("pin", stored)
        self.assertNotIn("token", stored)
        self.assertNotIn("biometric_encoding", stored)

    def test_audit_endpoints_reject_modifications(self):
        """Audit events cannot be created, modified, or deleted through the API."""
        dummy_id = uuid.uuid4()
        detail_url = f"{self.events_url}{dummy_id}/"

        res_post = self.client.post(self.events_url, {"event_type": "FORGED"})
        res_put = self.client.put(detail_url, {"event_type": "TAMPERED"})
        res_patch = self.client.patch(detail_url, {"result": "ALTERED"})
        res_delete = self.client.delete(detail_url)

        self.assertEqual(res_post.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        self.assertEqual(res_put.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        self.assertEqual(res_patch.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        self.assertEqual(res_delete.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
