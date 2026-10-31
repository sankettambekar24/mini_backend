"""Audit event model — append-only security event records."""

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class AuditEventType(models.TextChoices):
    LOGIN_SUCCESS = "LOGIN_SUCCESS", "Login Success"
    LOGIN_FAILED = "LOGIN_FAILED", "Login Failed"
    LOGIN_LOCKED_OUT = "LOGIN_LOCKED_OUT", "Login Locked Out"
    LOGOUT = "LOGOUT", "Logout"
    TOKEN_REFRESH = "TOKEN_REFRESH", "Token Refresh"
    PASSWORD_CHANGED = "PASSWORD_CHANGED", "Password Changed"
    PASSWORD_CHANGE_FAILED = "PASSWORD_CHANGE_FAILED", "Password Change Failed"
    USER_REGISTERED = "USER_REGISTERED", "User Registered"
    ADMIN_BOOTSTRAP = "ADMIN_BOOTSTRAP", "Admin Bootstrap"
    ADMIN_USER_CREATED = "ADMIN_USER_CREATED", "Admin User Created"
    ADMIN_USER_UPDATED = "ADMIN_USER_UPDATED", "Admin User Updated"
    USER_ACTIVATED = "USER_ACTIVATED", "User Activated"
    USER_DEACTIVATED = "USER_DEACTIVATED", "User Deactivated"
    USER_ROLE_CHANGED = "USER_ROLE_CHANGED", "User Role Changed"
    FILE_METADATA_REGISTERED = "FILE_METADATA_REGISTERED", "File Metadata Registered"
    FILE_GRANT_CREATED = "FILE_GRANT_CREATED", "File Grant Created"
    FILE_GRANT_REVOKED = "FILE_GRANT_REVOKED", "File Grant Revoked"


class AuditEvent(models.Model):
    """
    Append-only security event record.

    Security rules:
    - Never store passwords, PINs, tokens, keys, or raw biometric data here.
    - safe_metadata must be allowlisted before writing.
    - Records must never be updated or deleted in production.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    occurred_at = models.DateTimeField(default=timezone.now, db_index=True)

    # Actor may be null for pre-authentication events (e.g. failed login with unknown user).
    actor_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="audit_events",
        db_index=True,
    )

    # FK to Device and AuthAttempt added in later phases; stored as nullable strings
    # for Phase 1 to avoid circular import issues between apps.
    device_ref = models.CharField(max_length=64, blank=True, default="")
    auth_attempt_ref = models.CharField(max_length=64, blank=True, default="")

    event_type = models.CharField(max_length=64, db_index=True)
    result = models.CharField(max_length=32)
    correlation_id = models.CharField(max_length=64, blank=True, default="")

    # Allowlisted metadata only — no secrets, no raw request bodies.
    safe_metadata = models.JSONField(default=dict)

    class Meta:
        db_table = "audit_event"
        ordering = ["-occurred_at"]
        # Prevent accidental updates — enforced here but also in views.
        default_permissions = ("add", "view")

    def __str__(self):
        return f"{self.event_type} / {self.result} @ {self.occurred_at.isoformat()}"
