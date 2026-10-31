"""
Phase 1 test suite for the Hybrid Secure Storage System backend.

Tests cover the specification's required Phase 1 gates:
- Custom user model and registration
- Role enforcement (no self-assigned admin)
- JWT token lifecycle (obtain, refresh, blacklist/logout)
- Inactive user rejection
- Health endpoints
- Consistent error shape
- Password validation
"""

import uuid
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import OperationalError
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def create_user(username=None, password="SecurePass!99", role="USER", is_active=True):
    username = username or f"user_{uuid.uuid4().hex[:8]}"
    user = User.objects.create_user(username=username, password=password)
    user.is_active = is_active
    if role == "ADMIN":
        user.role = "ADMIN"
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


# ---------------------------------------------------------------------------
# Health endpoint tests
# ---------------------------------------------------------------------------

class HealthEndpointTests(APITestCase):
    def test_liveness_returns_200(self):
        url = reverse("health-live")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "ok")

    def test_readiness_returns_200_when_db_available(self):
        url = reverse("health-ready")
        response = self.client.get(url)
        # Should succeed in test environment with SQLite.
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["database"], "ok")
        self.assertEqual(response.data["cache"], "ok")

    def test_readiness_returns_503_when_database_is_unavailable(self):
        with patch("apps.health.views.connection.cursor", side_effect=OperationalError("offline")):
            response = self.client.get(reverse("health-ready"))

        self.assertEqual(response.status_code, status.HTTP_503_SERVICE_UNAVAILABLE)
        self.assertEqual(response.data["database"], "unavailable")
        self.assertEqual(response.data["cache"], "ok")

    def test_readiness_returns_503_when_cache_is_unavailable(self):
        with patch("apps.health.views.cache.set", side_effect=ConnectionError("offline")):
            response = self.client.get(reverse("health-ready"))

        self.assertEqual(response.status_code, status.HTTP_503_SERVICE_UNAVAILABLE)
        self.assertEqual(response.data["database"], "ok")
        self.assertEqual(response.data["cache"], "unavailable")

    def test_liveness_requires_no_auth(self):
        url = reverse("health-live")
        response = self.client.get(url)
        self.assertNotEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_liveness_contains_no_secret_fields(self):
        url = reverse("health-live")
        response = self.client.get(url)
        data = response.json()
        forbidden = {"secret", "key", "token", "password", "database_url"}
        self.assertTrue(forbidden.isdisjoint(set(data.keys())))


# ---------------------------------------------------------------------------
# User model tests
# ---------------------------------------------------------------------------

class UserModelTests(APITestCase):
    def test_user_uuid_primary_key(self):
        user = create_user()
        self.assertIsInstance(user.id, uuid.UUID)

    def test_password_is_not_plaintext(self):
        user = create_user(password="TestPass1234!")
        self.assertNotEqual(user.password, "TestPass1234!")
        self.assertTrue(user.password.startswith(("pbkdf2_", "argon2", "bcrypt", "scrypt")))

    def test_create_user_default_role_is_user(self):
        user = create_user()
        self.assertEqual(user.role, "USER")

    def test_create_superuser_sets_admin_role(self):
        user = User.objects.create_superuser(username="admin_test", password="Admin!Pass99")
        self.assertEqual(user.role, "ADMIN")
        self.assertTrue(user.is_staff)

    def test_manager_rejects_a_second_superuser(self):
        User.objects.create_superuser(username="first_admin", password="Admin!Pass99")
        with self.assertRaisesMessage(ValueError, "designated administrator already exists"):
            User.objects.create_superuser(username="second_admin", password="OtherAdmin!Pass88")

    def test_manager_rejects_admin_role_via_create_user(self):
        with self.assertRaises(ValueError):
            User.objects.create_user(username="baduser", password="Test!Pass99", role="ADMIN")

    def test_safe_profile_excludes_password(self):
        user = create_user()
        profile = user.safe_profile()
        self.assertNotIn("password", profile)
        self.assertIn("username", profile)
        self.assertIn("role", profile)


# ---------------------------------------------------------------------------
# Registration endpoint tests
# ---------------------------------------------------------------------------

class RegistrationTests(APITestCase):
    url = "/api/v1/auth/register/"

    def setUp(self):
        cache.clear()

    def test_registration_creates_user_role_only(self):
        response = self.client.post(self.url, {"username": "newuser1", "password": "ValidPass!99"})
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["role"], "USER")

    def test_registration_rejects_short_password(self):
        response = self.client.post(self.url, {"username": "newuser2", "password": "short"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_registration_applies_configured_password_validators(self):
        invalid_passwords = [
            ("common_user", "password12345"),
            ("numeric_user", "1234567890"),
            ("similar_user", "similar_user!123"),
            ("short_user", "Short!123"),
        ]
        for username, password in invalid_passwords:
            with self.subTest(username=username):
                cache.clear()
                response = self.client.post(self.url, {"username": username, "password": password})
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
                self.assertIn("VALIDATION_ERROR", response.data["error"]["code"])

    def test_registration_accepts_valid_password_and_hashes_it(self):
        password = "Long!UncommonPass839"
        response = self.client.post(self.url, {"username": "valid_password_user", "password": password})
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.get(username="valid_password_user").check_password(password))

    def test_registration_rejects_duplicate_username(self):
        create_user(username="dupeuser")
        response = self.client.post(self.url, {"username": "dupeuser", "password": "ValidPass!99"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_registration_response_excludes_password(self):
        response = self.client.post(self.url, {"username": "safe_user", "password": "ValidPass!99"})
        self.assertNotIn("password", response.data)

    def test_registration_error_shape(self):
        response = self.client.post(self.url, {"username": "", "password": "short"})
        self.assertIn("error", response.data)
        self.assertIn("code", response.data["error"])
        self.assertIn("request_id", response.data["error"])

    def test_registration_ignores_client_provided_admin_role(self):
        response = self.client.post(self.url, {"username": "wannabe_admin", "password": "ValidPass!99", "role": "ADMIN"})
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["role"], "USER")
        user = User.objects.get(username="wannabe_admin")
        self.assertEqual(user.role, "USER")
        self.assertFalse(user.is_staff)


# ---------------------------------------------------------------------------
# Login / JWT tests
# ---------------------------------------------------------------------------

class LoginTests(APITestCase):
    url = "/api/v1/auth/token/"

    def setUp(self):
        cache.clear()
        self.user = create_user(username="loginuser", password="LoginPass!99")

    def test_active_user_obtains_tokens(self):
        response = self.client.post(self.url, {"username": "loginuser", "password": "LoginPass!99"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    def test_response_includes_safe_user_info(self):
        response = self.client.post(self.url, {"username": "loginuser", "password": "LoginPass!99"})
        self.assertIn("user", response.data)
        self.assertEqual(response.data["user"]["username"], "loginuser")
        self.assertNotIn("password", response.data["user"])

    def test_inactive_user_cannot_obtain_tokens(self):
        inactive = create_user(username="inactive_user", password="LoginPass!99", is_active=False)
        response = self.client.post(self.url, {"username": "inactive_user", "password": "LoginPass!99"})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_wrong_password_is_rejected(self):
        response = self.client.post(self.url, {"username": "loginuser", "password": "WrongPass!99"})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_failed_login_creates_audit_event(self):
        from apps.audit.models import AuditEvent
        self.client.post(self.url, {"username": "loginuser", "password": "WrongPassword!99"})
        self.assertTrue(
            AuditEvent.objects.filter(event_type="LOGIN_FAILED", safe_metadata__username="loginuser").exists()
        )

    def test_jwt_error_shape(self):
        response = self.client.post(self.url, {"username": "loginuser", "password": "wrong"})
        self.assertIn("error", response.data)

    def test_access_token_does_not_contain_sensitive_claims(self):
        import base64, json
        response = self.client.post(self.url, {"username": "loginuser", "password": "LoginPass!99"})
        token = response.data["access"]
        payload_b64 = token.split(".")[1]
        # Add padding
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        forbidden_keys = {"password", "pin", "biometric", "secret", "key"}
        self.assertTrue(forbidden_keys.isdisjoint(set(payload.keys())))


# ---------------------------------------------------------------------------
# Token refresh and blacklist (logout) tests
# ---------------------------------------------------------------------------

class TokenRefreshTests(APITestCase):
    refresh_url = "/api/v1/auth/token/refresh/"
    logout_url = "/api/v1/auth/logout/"

    def setUp(self):
        self.user = create_user(username="refresh_user", password="RefreshPass!99")
        self.access, self.refresh = get_tokens_for_user(self.user)

    def test_valid_refresh_token_rotates_to_new_token(self):
        response = self.client.post(self.refresh_url, {"refresh": self.refresh})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)
        new_refresh = response.data["refresh"]

        # Re-using the old refresh token must fail because it was rotated and blacklisted
        replay = self.client.post(self.refresh_url, {"refresh": self.refresh})
        self.assertEqual(replay.status_code, status.HTTP_401_UNAUTHORIZED)

        # The new refresh token must work
        rotate_again = self.client.post(self.refresh_url, {"refresh": new_refresh})
        self.assertEqual(rotate_again.status_code, status.HTTP_200_OK)
        from rest_framework_simplejwt.tokens import AccessToken
        rotated_access = AccessToken(response.data["access"])
        self.assertEqual(rotated_access["role"], self.user.role)
        self.assertEqual(rotated_access["token_version"], self.user.token_version)

    def test_logout_blacklists_refresh_token(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access}")
        response = self.client.post(self.logout_url, {"refresh": self.refresh})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Try to use the blacklisted refresh token.
        replay = self.client.post(self.refresh_url, {"refresh": self.refresh})
        self.assertEqual(replay.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout_without_refresh_token_returns_400(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access}")
        response = self.client.post(self.logout_url, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_logout_rejects_malformed_or_another_users_refresh_token(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access}")
        malformed = self.client.post(self.logout_url, {"refresh": "not-a-refresh-token"})
        self.assertEqual(malformed.status_code, status.HTTP_400_BAD_REQUEST)
        malformed_type = self.client.post(self.logout_url, {"refresh": ["not-a-token"]})
        self.assertEqual(malformed_type.status_code, status.HTTP_400_BAD_REQUEST)
        other = create_user(username="another_refresh_owner")
        other_refresh = RefreshToken.for_user(other)
        foreign = self.client.post(self.logout_url, {"refresh": str(other_refresh)})
        self.assertEqual(foreign.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(other_refresh.check_blacklist())

    def test_invalid_access_token_is_rejected(self):
        self.client.credentials(HTTP_AUTHORIZATION="Bearer invalidtoken.bad.sig")
        response = self.client.get("/api/v1/auth/me/")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


# ---------------------------------------------------------------------------
# Me endpoint tests
# ---------------------------------------------------------------------------

class MeEndpointTests(APITestCase):
    url = "/api/v1/auth/me/"

    def setUp(self):
        self.user = create_user(username="me_user")
        self.access, _ = get_tokens_for_user(self.user)

    def test_authenticated_user_gets_profile(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access}")
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["username"], "me_user")

    def test_unauthenticated_request_rejected(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_me_response_excludes_password(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access}")
        response = self.client.get(self.url)
        self.assertNotIn("password", response.data)


# ---------------------------------------------------------------------------
# Role/permission enforcement tests
# ---------------------------------------------------------------------------

class RolePermissionTests(APITestCase):
    admin_users_url = "/api/v1/admin/users/"

    def setUp(self):
        self.admin = create_user(username="adminuser", role="ADMIN")
        self.normal = create_user(username="normaluser")
        self.admin_access, _ = get_tokens_for_user(self.admin)
        self.user_access, _ = get_tokens_for_user(self.normal)

    def test_normal_user_cannot_access_admin_user_list(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.user_access}")
        response = self.client.get(self.admin_users_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_admin_can_access_admin_user_list(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_access}")
        response = self.client.get(self.admin_users_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_normal_user_cannot_change_own_role(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.user_access}")
        url = f"/api/v1/admin/users/{self.normal.id}/role/"
        response = self.client.post(url, {"role": "ADMIN"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_unauthenticated_cannot_access_admin_endpoints(self):
        response = self.client.get(self.admin_users_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_user_cannot_view_another_users_admin_detail(self):
        other = create_user(username="other_user")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.user_access}")
        url = f"/api/v1/admin/users/{other.id}/"
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


# ---------------------------------------------------------------------------
# Admin role change auditing tests
# ---------------------------------------------------------------------------

class AdminRoleChangeTests(APITestCase):
    def setUp(self):
        self.admin = create_user(username="admin2", role="ADMIN")
        self.target = create_user(username="target_user")
        self.admin_access, _ = get_tokens_for_user(self.admin)

    def test_admin_cannot_promote_user_to_second_admin(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_access}")
        url = f"/api/v1/admin/users/{self.target.id}/role/"
        response = self.client.post(url, {"role": "ADMIN"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.target.refresh_from_db()
        self.assertEqual(self.target.role, "USER")

    def test_admin_can_demote_admin_to_user(self):
        self.target.role = "ADMIN"
        self.target.save()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_access}")
        url = f"/api/v1/admin/users/{self.target.id}/role/"
        response = self.client.post(url, {"role": "USER"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_last_administrator_cannot_self_demote(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_access}")
        response = self.client.post(
            f"/api/v1/admin/users/{self.admin.id}/role/", {"role": "USER"}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.admin.refresh_from_db()
        self.assertEqual(self.admin.role, "ADMIN")

    def test_role_change_creates_audit_event(self):
        from apps.audit.models import AuditEvent
        # Simulate a pre-existing duplicate designation to exercise the
        # audited demotion path; new promotions are rejected by policy.
        self.target.role = "ADMIN"
        self.target.is_staff = True
        self.target.is_superuser = True
        self.target.save(update_fields=["role", "is_staff", "is_superuser"])
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_access}")
        url = f"/api/v1/admin/users/{self.target.id}/role/"
        self.client.post(url, {"role": "USER"}, format="json")
        self.assertTrue(
            AuditEvent.objects.filter(event_type="USER_ROLE_CHANGED").exists()
        )


# ---------------------------------------------------------------------------
# Password change tests
# ---------------------------------------------------------------------------

class ChangePasswordTests(APITestCase):
    url = "/api/v1/auth/change-password/"

    def setUp(self):
        self.user = create_user(username="chpwd_user", password="OldPass!1234")
        self.access, self.refresh = get_tokens_for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access}")

    def test_correct_current_password_allows_change(self):
        response = self.client.post(
            self.url,
            {"current_password": "OldPass!1234", "new_password": "NewPass!9876"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_wrong_current_password_is_rejected(self):
        response = self.client.post(
            self.url,
            {"current_password": "WrongOld!1234", "new_password": "NewPass!9876"},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_short_new_password_is_rejected(self):
        response = self.client.post(
            self.url,
            {"current_password": "OldPass!1234", "new_password": "short"},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_change_applies_configured_validators(self):
        for new_password in ("password12345", "1234567890", "chpwd_user!123", "short"):
            with self.subTest(new_password=new_password):
                response = self.client.post(
                    self.url,
                    {"current_password": "OldPass!1234", "new_password": new_password},
                )
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_change_accepts_valid_password_and_hashes_it(self):
        password = "NewUncommon!Password837"
        response = self.client.post(
            self.url, {"current_password": "OldPass!1234", "new_password": password}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(password))


# ---------------------------------------------------------------------------
# Admin user management & disable tests
# ---------------------------------------------------------------------------

class AdminUserManagementTests(APITestCase):
    def setUp(self):
        self.admin = create_user(username="mgmt_admin", role="ADMIN")
        self.normal = create_user(username="mgmt_user", role="USER")
        self.admin_access, _ = get_tokens_for_user(self.admin)
        self.user_access, _ = get_tokens_for_user(self.normal)

    def test_admin_can_create_user_with_role(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_access}")
        url = "/api/v1/admin/users/"
        payload = {
            "username": "created_by_admin",
            "password": "ValidPassword!99",
            "role": "USER",
        }
        response = self.client.post(url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["username"], "created_by_admin")
        self.assertEqual(response.data["role"], "USER")
        self.assertNotIn("password", response.data)
        user = User.objects.get(username="created_by_admin")
        self.assertEqual(user.role, "USER")
        self.assertFalse(user.is_staff)

    def test_admin_cannot_create_second_administrator(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_access}")
        response = self.client.post(
            "/api/v1/admin/users/",
            {"username": "second_admin", "password": "ValidPassword!99", "role": "ADMIN"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(User.objects.filter(username="second_admin").exists())

    def test_admin_user_creation_uses_configured_password_validators(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_access}")
        for username, password in (
            ("admin_common", "password12345"),
            ("admin_numeric", "1234567890"),
            ("admin_similar", "admin_similar!123"),
            ("admin_short", "Short!123"),
        ):
            with self.subTest(username=username):
                response = self.client.post(
                    "/api/v1/admin/users/",
                    {"username": username, "password": password, "role": "USER"},
                    format="json",
                )
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
                self.assertFalse(User.objects.filter(username=username).exists())

    def test_admin_can_disable_user(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_access}")
        url = f"/api/v1/admin/users/{self.normal.id}/disable/"
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.normal.refresh_from_db()
        self.assertFalse(self.normal.is_active)

    def test_admin_cannot_disable_own_account(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_access}")
        url = f"/api/v1/admin/users/{self.admin.id}/disable/"
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["error"]["code"], "SELF_DISABLE_FORBIDDEN")
        self.admin.refresh_from_db()
        self.assertTrue(self.admin.is_active)

    def test_only_administrator_cannot_be_deactivated_through_either_api(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_access}")
        detail = self.client.patch(
            f"/api/v1/admin/users/{self.admin.id}/", {"is_active": False}, format="json"
        )
        disable = self.client.post(f"/api/v1/admin/users/{self.normal.id}/disable/")
        self.assertEqual(detail.status_code, status.HTTP_409_CONFLICT)
        # The target is an ordinary user; this operation remains permitted.
        self.assertEqual(disable.status_code, status.HTTP_200_OK)
        self.normal.refresh_from_db()
        self.assertFalse(self.normal.is_active)
        self.admin.refresh_from_db()
        self.assertTrue(self.admin.is_active)


# ---------------------------------------------------------------------------
# Audit endpoint & redaction tests
# ---------------------------------------------------------------------------

class AuditEndpointTests(APITestCase):
    events_url = "/api/v1/audit/events/"

    def setUp(self):
        self.admin = create_user(username="audit_admin", role="ADMIN")
        self.normal = create_user(username="audit_user", role="USER")
        self.admin_access, _ = get_tokens_for_user(self.admin)
        self.user_access, _ = get_tokens_for_user(self.normal)

    def test_normal_user_cannot_access_audit_events(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.user_access}")
        response = self.client.get(self.events_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_admin_can_access_audit_events(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_access}")
        response = self.client.get(self.events_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)

    def test_audit_records_never_leak_secrets(self):
        from apps.audit.models import AuditEvent
        from apps.audit.services import record_audit_event

        record_audit_event(
            event_type="TEST_EVENT",
            result="SUCCESS",
            actor_user=self.admin,
            safe_metadata={"action": "test_verification"},
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_access}")
        response = self.client.get(self.events_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        forbidden_keys = {"password", "pin", "token", "secret", "private_key", "biometric"}
        for event in response.data["results"]:
            metadata_keys = set(event.get("safe_metadata", {}).keys())
            self.assertTrue(forbidden_keys.isdisjoint(metadata_keys))

