import uuid
from datetime import timedelta
from unittest import skipUnless

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import close_old_connections, connection, connections
from django.db import DatabaseError, transaction
from django.test import TestCase, TransactionTestCase
from django.utils import timezone
from rest_framework.test import APIClient

from apps.audit.models import AuditEvent
from apps.devices.models import Device, DeviceStatus
from apps.hardware_auth.models import AttemptStatus, AuthAttempt, AuthAttemptEvent
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


def token_for(user):
    token = RefreshToken.for_user(user)
    token["token_version"] = user.token_version
    token["role"] = user.role
    return str(token.access_token)


class Phase3APITests(TestCase):
    def setUp(self):
        cache.clear()
        self.admin = User.objects.create_superuser(username="phase3_admin", password="StrongPassword!99")
        self.user = User.objects.create_user(username="phase3_user", password="StrongPassword!99")
        self.other = User.objects.create_user(username="phase3_other", password="StrongPassword!99")
        self.device = Device.objects.create(
            device_label="Test STM32", device_public_id="public-test-id", owner_user=self.user,
            status=DeviceStatus.ACTIVE,
        )
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def create_attempt(self):
        response = self.client.post("/api/v1/auth-attempts/", {"device_id": str(self.device.id)}, format="json")
        self.assertEqual(response.status_code, 201, response.data)
        return response.data["id"]

    def report_face(self, attempt_id, event_id=None, device_id=None):
        return self.client.post(
            f"/api/v1/auth-attempts/{attempt_id}/events/",
            {
                "contract_version": 1,
                "event_id": str(event_id or uuid.uuid4()),
                "device_id": str(device_id or self.device.id),
                "factor": "FACE",
            },
            format="json",
        )

    def test_only_admin_can_enroll_and_transition_devices(self):
        response = self.client.post("/api/v1/devices/", {
            "device_label": "Other", "device_public_id": "other-id", "owner_user": str(self.user.id),
        }, format="json")
        self.assertEqual(response.status_code, 403)
        self.client.force_authenticate(self.admin)
        response = self.client.post("/api/v1/devices/", {
            "device_label": "Other", "device_public_id": "other-id", "owner_user": str(self.user.id),
        }, format="json")
        self.assertEqual(response.status_code, 201, response.data)
        new_id = response.data["id"]
        response = self.client.post(f"/api/v1/devices/{new_id}/status/", {"status": "ACTIVE"}, format="json")
        self.assertEqual(response.status_code, 200)
        response = self.client.post(f"/api/v1/devices/{new_id}/status/", {"status": "PENDING"}, format="json")
        self.assertEqual(response.status_code, 400)

    def test_device_status_audit_and_strict_failure_rollback(self):
        from unittest.mock import patch
        from apps.audit import services as audit_services

        with patch("apps.devices.services.record_audit_event", side_effect=RuntimeError("audit unavailable")):
            from apps.devices.services import change_device_status
            with self.assertRaises(RuntimeError):
                change_device_status(self.device.id, DeviceStatus.LOST, self.admin)
        self.device.refresh_from_db()
        self.assertEqual(self.device.status, DeviceStatus.ACTIVE)

        self.client.force_authenticate(self.admin)
        response = self.client.post(f"/api/v1/devices/{self.device.id}/status/", {"status": "LOST"}, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(AuditEvent.objects.filter(event_type="DEVICE_STATUS_CHANGED", device_ref=str(self.device.id)).exists())

    def test_attempt_binds_authenticated_user_and_active_owned_device(self):
        self.client.force_authenticate(self.other)
        response = self.client.post("/api/v1/auth-attempts/", {"device_id": str(self.device.id)}, format="json")
        self.assertEqual(response.status_code, 403)

        self.client.force_authenticate(self.user)
        attempt_id = self.create_attempt()
        attempt = AuthAttempt.objects.get(id=attempt_id)
        self.assertEqual(attempt.expires_at - attempt.created_at, timedelta(seconds=300))
        self.assertEqual(attempt.required_factors, ["PIN", "FACE", "FINGERPRINT"])

    def test_expired_attempt_is_terminal_and_rejected(self):
        attempt_id = self.create_attempt()
        AuthAttempt.objects.filter(id=attempt_id).update(expires_at=timezone.now())
        response = self.report_face(attempt_id)
        self.assertEqual(response.status_code, 410)
        attempt = AuthAttempt.objects.get(id=attempt_id)
        self.assertEqual(attempt.status, AttemptStatus.EXPIRED)
        self.assertEqual(attempt.events.count(), 0)

    def test_replay_duplicate_factor_and_binding_mismatches_are_rejected(self):
        attempt_id = self.create_attempt()
        event_id = uuid.uuid4()
        self.assertEqual(self.report_face(attempt_id, event_id).status_code, 201)
        self.assertEqual(self.report_face(attempt_id, event_id).data["error"]["code"], "REPLAYED_EVENT")
        self.assertEqual(self.report_face(attempt_id).data["error"]["code"], "DUPLICATE_FACTOR")
        self.assertEqual(self.report_face(attempt_id, device_id=uuid.uuid4()).status_code, 403)

        self.client.force_authenticate(self.other)
        response = self.report_face(attempt_id)
        self.assertEqual(response.status_code, 403)

    def test_unverified_reports_never_complete_attempt(self):
        attempt_id = self.create_attempt()
        response = self.client.post(
            f"/api/v1/auth-attempts/{attempt_id}/events/",
            {"contract_version": 1, "event_id": str(uuid.uuid4()), "device_id": str(self.device.id),
             "factor": "FACE", "matched": True, "verified": True},
            format="json",
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["reported_event"]["evidence_class"], "HOST_ASSERTION")
        self.assertFalse(response.data["reported_event"]["verified"])
        response = self.client.post(
            f"/api/v1/auth-attempts/{attempt_id}/complete/", {"device_id": str(self.device.id)}, format="json"
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data["error"]["code"], "FACTOR_VERIFICATION_UNAVAILABLE")
        self.assertEqual(AuthAttempt.objects.get(id=attempt_id).status, AttemptStatus.FACTORS_PENDING)
        self.assertTrue(AuditEvent.objects.filter(
            event_type="AUTH_ATTEMPT_COMPLETION_BLOCKED", auth_attempt_ref=attempt_id
        ).exists())

    def test_cancelled_attempt_cannot_be_completed_or_replayed(self):
        attempt_id = self.create_attempt()
        response = self.client.post(
            f"/api/v1/auth-attempts/{attempt_id}/cancel/", {"device_id": str(self.device.id)}, format="json"
        )
        self.assertEqual(response.status_code, 200)
        response = self.client.post(
            f"/api/v1/auth-attempts/{attempt_id}/complete/", {"device_id": str(self.device.id)}, format="json"
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data["error"]["code"], "INVALID_ATTEMPT_STATE")

    def test_revoked_device_fails_attempt_and_prevents_new_attempts(self):
        attempt_id = self.create_attempt()
        self.device.status = DeviceStatus.REVOKED
        self.device.save(update_fields=["status"])
        response = self.report_face(attempt_id)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(AuthAttempt.objects.get(id=attempt_id).status, AttemptStatus.FAILED)
        response = self.client.post("/api/v1/auth-attempts/", {"device_id": str(self.device.id)}, format="json")
        self.assertEqual(response.status_code, 403)

    def test_attempt_security_events_are_audited_without_factor_payload(self):
        attempt_id = self.create_attempt()
        event_id = uuid.uuid4()
        response = self.report_face(attempt_id, event_id)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(self.report_face(attempt_id, event_id).status_code, 409)
        event = AuditEvent.objects.get(event_type="AUTH_FACTOR_REPORTED")
        self.assertEqual(event.auth_attempt_ref, attempt_id)
        self.assertEqual(event.safe_metadata["evidence_class"], "HOST_ASSERTION")
        self.assertNotIn("matched", event.safe_metadata)
        self.assertTrue(AuditEvent.objects.filter(
            event_type="AUTH_ATTEMPT_EVENT_REJECTED", auth_attempt_ref=attempt_id,
            safe_metadata__reason="replayed_event",
        ).exists())


class AdminBootstrapAuditFailureTests(TestCase):
    def test_failed_bootstrap_audit_rolls_back_admin_creation(self):
        from unittest.mock import patch
        from django.core.management import call_command
        from apps.accounts.management.commands import bootstrap_admin

        with patch.object(bootstrap_admin, "record_audit_event", side_effect=RuntimeError("audit unavailable")):
            with self.assertRaises(RuntimeError):
                call_command("bootstrap_admin", username="audit_fail_admin", password="StrongPassword!99", no_input=True)
        self.assertFalse(User.objects.filter(username="audit_fail_admin").exists())

    def test_password_change_rolls_back_when_audit_write_fails(self):
        from unittest.mock import patch

        self.user = User.objects.create_user(username="audit_rollback_user", password="StrongPassword!99")
        client = APIClient()
        client.force_authenticate(self.user)
        client.raise_request_exception = False
        with patch("apps.authentication.views.record_audit_event", side_effect=RuntimeError("audit unavailable")):
            response = client.post(
                "/api/v1/auth/change-password/",
                {"current_password": "StrongPassword!99", "new_password": "NewStrongPassword!99"},
                format="json",
            )
        self.assertEqual(response.status_code, 500)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("StrongPassword!99"))

    def test_audit_service_raises_on_write_failure_by_default(self):
        from unittest.mock import patch
        from apps.audit.services import record_audit_event

        with patch("apps.audit.models.AuditEvent.objects.create", side_effect=RuntimeError("database unavailable")):
            with self.assertRaises(RuntimeError):
                record_audit_event("TEST_STRICT_DEFAULT", "FAILURE", safe_metadata={})

    def test_audit_rows_cannot_be_updated_or_deleted_in_database(self):
        event = AuditEvent.objects.create(event_type="IMMUTABILITY_TEST", result="CREATED")
        with self.assertRaises(DatabaseError):
            with transaction.atomic():
                AuditEvent.objects.filter(id=event.id).update(result="ALTERED")
        with self.assertRaises(DatabaseError):
            with transaction.atomic():
                AuditEvent.objects.filter(id=event.id).delete()
        event.refresh_from_db()
        self.assertEqual(event.result, "CREATED")


@skipUnless(connection.vendor == "postgresql", "PostgreSQL row-lock integration test")
class PostgreSQLAttemptConcurrencyTests(TransactionTestCase):
    reset_sequences = True

    def test_concurrent_replay_allows_exactly_one_factor_event(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier

        user = User.objects.create_user(username="pg_race_user", password="StrongPassword!99")
        device = Device.objects.create(
            device_label="Postgres race", device_public_id="pg-race-id", owner_user=user,
            status=DeviceStatus.ACTIVE,
        )
        attempt = AuthAttempt.objects.create(
            user=user, device=device, status=AttemptStatus.PENDING,
            required_factors=["PIN", "FACE", "FINGERPRINT"], expires_at=timezone.now() + timedelta(minutes=5),
        )
        event_id = uuid.uuid4()
        token = token_for(user)
        barrier = Barrier(2)

        def send_event():
            close_old_connections()
            try:
                client = APIClient()
                client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
                barrier.wait()
                response = client.post(
                    f"/api/v1/auth-attempts/{attempt.id}/events/",
                    {"contract_version": 1, "event_id": str(event_id), "device_id": str(device.id), "factor": "FACE"},
                    format="json",
                )
                return response.status_code
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: send_event(), range(2)))
        self.assertCountEqual(results, [201, 409])
        self.assertEqual(AuthAttemptEvent.objects.filter(attempt=attempt).count(), 1)

    def test_concurrent_admin_bootstrap_creates_at_most_one_admin(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        from django.core.management import call_command
        from django.core.management.base import CommandError

        barrier = Barrier(2)

        def bootstrap(username):
            close_old_connections()
            try:
                barrier.wait()
                call_command("bootstrap_admin", username=username, password="StrongPassword!99", no_input=True)
                result = "created"
            except CommandError:
                result = "rejected"
            finally:
                connections.close_all()
            return result

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(bootstrap, ["pg_admin_one", "pg_admin_two"]))
        self.assertCountEqual(results, ["created", "rejected"])
        self.assertEqual(User.objects.filter(role="ADMIN").count(), 1)
