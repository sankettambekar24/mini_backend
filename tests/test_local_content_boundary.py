
from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from apps.accounts.models import UserRole
from apps.storage.models import StoredFileMetadata

User = get_user_model()


class FileContentBoundaryTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            username="content_owner_test",
            password="Temporary-Test-Password-42!",
            role=UserRole.USER,
        )
        self.other_user = User.objects.create_user(
            username="content_other_test",
            password="Temporary-Test-Password-43!",
            role=UserRole.USER,
        )
        self.file_record = StoredFileMetadata.objects.create(
            owner_user=self.owner,
            display_name="dummy-test-file.txt",
            size_bytes=0,
            encryption_format_version=0,
        )
        self.client = APIClient()

    def test_owner_is_authorized_but_content_is_unavailable(self):
        self.client.force_authenticate(user=self.owner)
        response = self.client.get(
            f"/api/v1/files/{self.file_record.id}/content/"
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.data["error"]["code"],
            "FILE_CONTENT_UNAVAILABLE",
        )

    def test_unrelated_user_cannot_access_content(self):
        self.client.force_authenticate(user=self.other_user)
        response = self.client.get(
            f"/api/v1/files/{self.file_record.id}/content/"
        )

        self.assertEqual(response.status_code, 404)

    def test_missing_authentication_is_rejected(self):
        response = self.client.get(
            f"/api/v1/files/{self.file_record.id}/content/"
        )

        self.assertEqual(response.status_code, 401)
