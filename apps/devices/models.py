"""Registered STM32 device records. IDs identify devices but do not attest them."""

import uuid
from django.conf import settings
from django.db import models
from django.utils import timezone


class DeviceStatus(models.TextChoices):
    PENDING = "PENDING", "Pending"
    ACTIVE = "ACTIVE", "Active"
    REVOKED = "REVOKED", "Revoked"
    LOST = "LOST", "Lost"


class Device(models.Model):
    """
    Device enrollment record.

    Security note: device_public_id is an identifier, NOT cryptographic proof
    of device authenticity. Hardware-backed challenge-response is Phase 7 work.
    A public device ID must never be treated as a trusted credential.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device_label = models.CharField(max_length=128)
    device_public_id = models.CharField(max_length=128, unique=True)
    owner_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="devices",
    )
    status = models.CharField(
        max_length=16,
        choices=DeviceStatus.choices,
        default=DeviceStatus.PENDING,
        db_index=True,
    )
    protocol_version = models.CharField(max_length=16, blank=True, default="")
    last_seen_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "device"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.device_label} ({self.status})"
