"""
Permission grant model — resource-level authorization.
The initial file API uses exact StoredFileMetadata UUIDs and LIST/READ scopes
for metadata authorization; it does not provide file-byte access.
"""

import uuid
from django.conf import settings
from django.db import models
from django.utils import timezone


class PermissionType(models.TextChoices):
    LIST = "LIST", "List"
    READ = "READ", "Read"
    WRITE = "WRITE", "Write"
    DELETE = "DELETE", "Delete"
    ADMINISTER = "ADMINISTER", "Administer"


class PermissionGrant(models.Model):
    """
    Resource-level permission grant.

    Default deny: backend checks this for every protected operation.
    Role label alone is NOT a substitute for resource-level authorization.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    subject_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="permission_grants",
    )
    # Resource identifier: refers to a StoredFileMetadata UUID or a named resource.
    resource_id = models.CharField(max_length=64, db_index=True)
    permission = models.CharField(max_length=16, choices=PermissionType.choices)
    granted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="granted_permissions",
    )
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "permission_grant"
        unique_together = [["subject_user", "resource_id", "permission"]]

    def is_active(self):
        now = timezone.now()
        # revoked_at records that the grant has been revoked, not a scheduled
        # revocation time. Any populated value therefore denies access.
        if self.revoked_at is not None:
            return False
        if self.expires_at and self.expires_at <= now:
            return False
        return True

    def __str__(self):
        return f"{self.subject_user} / {self.permission} / {self.resource_id}"
