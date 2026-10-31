"""Server-side records for signed offline-policy lifecycle metadata.

The model does not grant access by itself. Policy issuance remains disabled
until the server can verify device identity, file grants, trusted expiry, and
authentication evidence.
"""

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class OfflinePolicyStatus(models.TextChoices):
    PREPARED = "PREPARED", "Prepared"
    ISSUED = "ISSUED", "Issued"
    REVOKED = "REVOKED", "Revoked"
    EXPIRED = "EXPIRED", "Expired"
    SUPERSEDED = "SUPERSEDED", "Superseded"


class OfflinePolicyScope(models.TextChoices):
    LIST = "LIST", "List"
    READ = "READ", "Read"


class OfflinePolicy(models.Model):
    """One immutable, versioned signed-policy issue/revocation record."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    policy_id = models.UUIDField(default=uuid.uuid4, db_index=True)
    policy_version = models.PositiveIntegerField(default=1)
    schema_version = models.PositiveSmallIntegerField(default=1)
    nonce = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="offline_policies",
    )
    device = models.ForeignKey(
        "devices.Device",
        on_delete=models.PROTECT,
        related_name="offline_policies",
    )
    # A value can only be populated by a future verified hardware enrollment.
    device_key_id = models.CharField(max_length=128, blank=True, default="")
    scopes = models.ManyToManyField(
        "storage.StoredFileMetadata",
        through="OfflinePolicyFileScope",
        related_name="offline_policies",
    )
    status = models.CharField(
        max_length=16,
        choices=OfflinePolicyStatus.choices,
        default=OfflinePolicyStatus.PREPARED,
        db_index=True,
    )
    max_offline_seconds = models.PositiveIntegerField()
    issued_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True, db_index=True)
    signing_key_id = models.CharField(max_length=128, blank=True, default="")
    signed_policy = models.TextField(blank=True, default="")
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="revoked_offline_policies",
    )
    revocation_reason = models.CharField(max_length=64, blank=True, default="")
    superseded_by = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="supersedes",
    )
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "offline_policy"
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["policy_id", "policy_version"],
                name="uniq_offline_policy_version",
            ),
        ]

    def __str__(self):
        return f"OfflinePolicy {self.policy_id} v{self.policy_version} ({self.status})"


class OfflinePolicyFileScope(models.Model):
    """Frozen, stable-UUID file scope for one policy version."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    policy = models.ForeignKey(
        OfflinePolicy,
        on_delete=models.CASCADE,
        related_name="file_scopes",
    )
    file = models.ForeignKey(
        "storage.StoredFileMetadata",
        on_delete=models.PROTECT,
        related_name="offline_policy_scopes",
    )
    scope = models.CharField(max_length=8, choices=OfflinePolicyScope.choices)

    class Meta:
        db_table = "offline_policy_file_scope"
        constraints = [
            models.UniqueConstraint(
                fields=["policy", "file", "scope"],
                name="uniq_offline_policy_file_scope",
            ),
        ]

