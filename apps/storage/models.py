"""
File metadata model — metadata ONLY. No file content stored here.
The initial API registers metadata and grants only; physical storage access is
not implemented.

Security note: this model does NOT prove the SD-card file content is encrypted.
The actual encrypted-file format and key hierarchy must be designed and tested
separately (Phase 7).
"""

import uuid
from django.conf import settings
from django.db import models
from django.utils import timezone


class StoredFileMetadata(models.Model):
    """
    Stable UUID metadata record for a file managed by the system.
    Contains no file content. Encryption is NOT assumed or claimed.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="files",
    )
    device = models.ForeignKey(
        "devices.Device",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="files",
    )
    display_name = models.CharField(max_length=255)
    # Opaque storage locator — format defined in Phase 7.
    encrypted_object_id = models.CharField(max_length=255, blank=True, default="")
    size_bytes = models.BigIntegerField(default=0)
    # Encryption format version — 0 means not yet defined/implemented.
    encryption_format_version = models.IntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "stored_file_metadata"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.display_name} (owner={self.owner_user_id})"
