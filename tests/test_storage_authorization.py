import uuid
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from apps.audit.models import AuditEvent
from apps.permissions.models import PermissionGrant, PermissionType
from apps.storage.models import StoredFileMetadata


User = get_user_model()


class FileAuthorizationAPITests(TestCase):
    def setUp(self):
        cache.clear()
        self.admin = User.objects.create_superuser(
            username="file_admin", password="StrongPassword!99"
        )
        self.owner = User.objects.create_user(
            username="file_owner", password="StrongPassword!99"
        )
        self.other = User.objects.create_user(
            username="file_other", password="StrongPassword!99"
        )
        self.file = StoredFileMetadata.objects.create(
            owner_user=self.owner,
            display_name="report.txt",
            size_bytes=0,
            encryption_format_version=0,
        )
        self.client = APIClient()

    def grant(self, user, permission, *, expires_at=None, revoked_at=None):
        return PermissionGrant.objects.create(
            subject_user=user,
            resource_id=str(self.file.id),
            permission=permission,
            granted_by=self.owner,
            expires_at=expires_at,
            revoked_at=revoked_at,
        )

    def test_unauthenticated_metadata_grant_and_content_requests_are_rejected(self):
        self.assertEqual(self.client.get("/api/v1/files/").status_code, 401)
        self.assertEqual(self.client.get(f"/api/v1/files/{self.file.id}/").status_code, 401)
        self.assertEqual(self.client.get(f"/api/v1/files/{self.file.id}/content/").status_code, 401)
        self.assertEqual(
            self.client.post(f"/api/v1/files/{self.file.id}/grants/", {}, format="json").status_code,
            401,
        )

    def test_owner_can_list_and_read_own_metadata_but_content_is_unavailable(self):
        self.client.force_authenticate(self.owner)
        listed = self.client.get("/api/v1/files/")
        detail = self.client.get(f"/api/v1/files/{self.file.id}/")
        content = self.client.get(f"/api/v1/files/{self.file.id}/content/")

        self.assertEqual(listed.status_code, 200)
        self.assertEqual([row["id"] for row in listed.data["results"]], [str(self.file.id)])
        self.assertEqual(detail.status_code, 200)
        self.assertFalse(detail.data["content_available"])
        self.assertNotIn("encrypted_object_id", detail.data)
        self.assertEqual(content.status_code, 503)
        self.assertEqual(content.data["error"]["code"], "FILE_CONTENT_UNAVAILABLE")

    def test_user_cannot_access_another_users_metadata_or_content_without_grant(self):
        self.client.force_authenticate(self.other)
        listed = self.client.get("/api/v1/files/")
        detail = self.client.get(f"/api/v1/files/{self.file.id}/")
        content = self.client.get(f"/api/v1/files/{self.file.id}/content/")

        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.data["results"], [])
        self.assertEqual(detail.status_code, 404)
        self.assertEqual(content.status_code, 404)

    def test_list_grant_exposes_only_listing_metadata_not_detail_or_content(self):
        self.grant(self.other, PermissionType.LIST)
        self.client.force_authenticate(self.other)

        listed = self.client.get("/api/v1/files/")
        detail = self.client.get(f"/api/v1/files/{self.file.id}/")
        content = self.client.get(f"/api/v1/files/{self.file.id}/content/")

        self.assertEqual([row["id"] for row in listed.data["results"]], [str(self.file.id)])
        self.assertEqual(detail.status_code, 404)
        self.assertEqual(content.status_code, 404)

    def test_read_grant_allows_metadata_but_not_file_bytes(self):
        self.grant(self.other, PermissionType.READ)
        self.client.force_authenticate(self.other)

        self.assertEqual(self.client.get("/api/v1/files/").data["results"], [])
        self.assertEqual(self.client.get(f"/api/v1/files/{self.file.id}/").status_code, 200)
        content = self.client.get(f"/api/v1/files/{self.file.id}/content/")
        self.assertEqual(content.status_code, 503)
        self.assertEqual(content.data["error"]["code"], "FILE_CONTENT_UNAVAILABLE")

    def test_read_grant_expiry_is_enforced_at_each_request(self):
        grant = self.grant(
            self.other,
            PermissionType.READ,
            expires_at=timezone.now() + timedelta(minutes=5),
        )
        self.client.force_authenticate(self.other)
        self.assertEqual(self.client.get(f"/api/v1/files/{self.file.id}/").status_code, 200)

        grant.expires_at = timezone.now() - timedelta(seconds=1)
        grant.save(update_fields=["expires_at"])
        self.assertEqual(self.client.get(f"/api/v1/files/{self.file.id}/").status_code, 404)

    def test_revoked_and_expired_grants_do_not_authorize_access(self):
        revoked = self.grant(self.other, PermissionType.READ, revoked_at=timezone.now())
        self.client.force_authenticate(self.other)
        self.assertFalse(revoked.is_active())
        self.assertEqual(self.client.get(f"/api/v1/files/{self.file.id}/").status_code, 404)

        revoked.delete()
        expired = self.grant(
            self.other,
            PermissionType.READ,
            expires_at=timezone.now() - timedelta(seconds=1),
        )
        self.assertFalse(expired.is_active())
        self.assertEqual(self.client.get(f"/api/v1/files/{self.file.id}/").status_code, 404)

    def test_any_revocation_timestamp_disables_grant(self):
        grant = self.grant(
            self.other,
            PermissionType.READ,
            revoked_at=timezone.now() + timedelta(days=1),
        )
        self.assertFalse(grant.is_active())

    def test_only_admin_can_register_metadata_and_input_cannot_set_storage_fields(self):
        payload = {"owner_user_id": str(self.owner.id), "display_name": "new.txt"}
        self.client.force_authenticate(self.owner)
        self.assertEqual(
            self.client.post("/api/v1/files/metadata/", payload, format="json").status_code,
            403,
        )

        self.client.force_authenticate(self.admin)
        response = self.client.post("/api/v1/files/metadata/", payload, format="json")
        self.assertEqual(response.status_code, 201, response.data)
        self.assertFalse(response.data["content_available"])
        created = StoredFileMetadata.objects.get(id=response.data["id"])
        self.assertEqual(created.owner_user, self.owner)
        self.assertEqual(created.encrypted_object_id, "")
        self.assertEqual(created.size_bytes, 0)
        self.assertEqual(created.encryption_format_version, 0)
        self.assertTrue(AuditEvent.objects.filter(event_type="FILE_METADATA_REGISTERED").exists())

        bad_payload = {**payload, "encrypted_object_id": "client-controlled"}
        self.assertEqual(
            self.client.post("/api/v1/files/metadata/", bad_payload, format="json").status_code,
            400,
        )

    def test_display_name_rejects_paths_and_control_characters(self):
        self.client.force_authenticate(self.admin)
        for name in ("../secret.txt", "nested/file.txt", "nested\\file.txt", "bad\x00name"):
            response = self.client.post(
                "/api/v1/files/metadata/",
                {"owner_user_id": str(self.owner.id), "display_name": name},
                format="json",
            )
            self.assertEqual(response.status_code, 400, name)

    def test_admin_sees_metadata_and_manages_grants_but_has_no_implicit_content_access(self):
        self.client.force_authenticate(self.admin)
        self.assertEqual(self.client.get("/api/v1/files/").status_code, 200)
        self.assertEqual(self.client.get(f"/api/v1/files/{self.file.id}/").status_code, 200)
        self.assertEqual(self.client.get(f"/api/v1/files/{self.file.id}/content/").status_code, 404)

        response = self.client.post(
            f"/api/v1/files/{self.file.id}/grants/",
            {"subject_user_id": str(self.other.id), "permission": "READ"},
            format="json",
        )
        self.assertEqual(response.status_code, 201, response.data)

    def test_non_owner_cannot_create_or_inspect_grants(self):
        self.client.force_authenticate(self.other)
        existing_grant = self.grant(self.other, PermissionType.READ)
        payload = {"subject_user_id": str(self.owner.id), "permission": "READ"}
        self.assertEqual(
            self.client.post(f"/api/v1/files/{self.file.id}/grants/", payload, format="json").status_code,
            404,
        )
        self.assertEqual(self.client.get(f"/api/v1/files/{self.file.id}/grants/").status_code, 404)
        self.assertEqual(
            self.client.post(
                f"/api/v1/files/{self.file.id}/grants/{existing_grant.id}/revoke/", {}, format="json"
            ).status_code,
            404,
        )

    def test_grants_accept_only_metadata_scopes_and_future_expiry(self):
        self.client.force_authenticate(self.owner)
        base = {"subject_user_id": str(self.other.id)}
        for payload in (
            {**base, "permission": "WRITE"},
            {**base, "permission": "DELETE"},
            {**base, "permission": "ADMINISTER"},
            {**base, "permission": "READ", "expires_at": (timezone.now() - timedelta(seconds=1)).isoformat()},
            {**base, "permission": "READ", "resource_id": str(uuid.uuid4())},
        ):
            response = self.client.post(
                f"/api/v1/files/{self.file.id}/grants/", payload, format="json"
            )
            self.assertEqual(response.status_code, 400, response.data)

    def test_owner_can_create_revoke_and_regrant_with_audit_events(self):
        self.client.force_authenticate(self.owner)
        url = f"/api/v1/files/{self.file.id}/grants/"
        payload = {"subject_user_id": str(self.other.id), "permission": "READ"}
        created = self.client.post(url, payload, format="json")
        self.assertEqual(created.status_code, 201, created.data)
        grant_id = created.data["id"]
        self.assertTrue(AuditEvent.objects.filter(event_type="FILE_GRANT_CREATED").exists())

        duplicate = self.client.post(url, payload, format="json")
        self.assertEqual(duplicate.status_code, 409)

        revoked = self.client.post(f"{url}{grant_id}/revoke/", {}, format="json")
        self.assertEqual(revoked.status_code, 200, revoked.data)
        self.assertIsNotNone(PermissionGrant.objects.get(id=grant_id).revoked_at)
        self.assertTrue(AuditEvent.objects.filter(event_type="FILE_GRANT_REVOKED").exists())

        regranted = self.client.post(url, payload, format="json")
        self.assertEqual(regranted.status_code, 201, regranted.data)
        self.assertEqual(regranted.data["id"], grant_id)
        self.assertTrue(regranted.data["active"])

    def test_malformed_uuid_and_path_traversal_do_not_resolve_file_objects(self):
        self.client.force_authenticate(self.owner)
        self.assertEqual(self.client.get("/api/v1/files/not-a-uuid/").status_code, 404)
        self.assertEqual(self.client.get("/api/v1/files/%2e%2e%2fsecret/").status_code, 404)
        self.assertEqual(self.client.get("/api/v1/files/../secret/").status_code, 404)

    def test_audit_failure_rolls_back_metadata_creation(self):
        self.client.force_authenticate(self.admin)
        self.client.raise_request_exception = False
        with patch("apps.storage.services.record_audit_event", side_effect=RuntimeError("audit unavailable")):
            response = self.client.post(
                "/api/v1/files/metadata/",
                {"owner_user_id": str(self.owner.id), "display_name": "rolled-back.txt"},
                format="json",
            )
        self.assertEqual(response.status_code, 500)
        self.assertFalse(StoredFileMetadata.objects.filter(display_name="rolled-back.txt").exists())

    def test_audit_failure_rolls_back_grant_creation_and_revocation(self):
        self.client.force_authenticate(self.owner)
        self.client.raise_request_exception = False
        grants_url = f"/api/v1/files/{self.file.id}/grants/"
        payload = {"subject_user_id": str(self.other.id), "permission": "READ"}

        with patch("apps.storage.services.record_audit_event", side_effect=RuntimeError("audit unavailable")):
            create_response = self.client.post(grants_url, payload, format="json")
        self.assertEqual(create_response.status_code, 500)
        self.assertFalse(PermissionGrant.objects.filter(resource_id=str(self.file.id)).exists())

        grant = self.grant(self.other, PermissionType.READ)
        with patch("apps.storage.services.record_audit_event", side_effect=RuntimeError("audit unavailable")):
            revoke_response = self.client.post(
                f"{grants_url}{grant.id}/revoke/", {}, format="json"
            )
        self.assertEqual(revoke_response.status_code, 500)
        grant.refresh_from_db()
        self.assertIsNone(grant.revoked_at)
