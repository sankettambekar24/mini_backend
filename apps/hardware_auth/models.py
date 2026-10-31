"""Server-controlled authentication attempts and unverified factor reports.

Security design notes (for Phase 3):
- Every attempt gets a new random UUID and a short expiry.
- Factor evidence must bind to the SAME attempt, account, and device.
- Client reports are not factor success; they remain unverified until a
  backend or cryptographic evidence verifier is implemented.
- Face matching on the Windows host is a HOST ASSERTION, not a trusted proof.
  A compromised host can lie about the result. This limitation must be
  documented and mitigated with rate limits, short-lived transactions, and
  audit logs until stronger trusted capture/attestation is implemented.
- Fingerprint sensor events sent over plain serial are NOT cryptographic proof
  unless the protocol provides authenticated evidence.
"""

import uuid
from django.conf import settings
from django.db import models
from django.utils import timezone


class AttemptStatus(models.TextChoices):
    PENDING = "PENDING", "Pending"
    FACTORS_PENDING = "FACTORS_PENDING", "Factors Pending"
    FAILED = "FAILED", "Failed"
    EXPIRED = "EXPIRED", "Expired"
    CANCELLED = "CANCELLED", "Cancelled"


class AuthAttempt(models.Model):
    """
    Transactional hardware authentication attempt.

    Each attempt has a short expiry. Factors from different attempts
    cannot be combined. The backend is the authority for attempt status.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="auth_attempts",
    )
    device = models.ForeignKey(
        "devices.Device",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="auth_attempts",
    )
    status = models.CharField(
        max_length=20,
        choices=AttemptStatus.choices,
        default=AttemptStatus.PENDING,
        db_index=True,
    )
    required_factors = models.JSONField(default=list)
    completed_factors = models.JSONField(default=list)
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(db_index=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    # Safe enumerated failure code only — no raw exception details.
    failure_code = models.CharField(max_length=64, blank=True, default="")

    class Meta:
        db_table = "auth_attempt"
        ordering = ["-created_at"]

    def is_expired(self):
        return timezone.now() >= self.expires_at

    def __str__(self):
        return f"AuthAttempt {self.id} ({self.status})"


class AuthAttemptEvent(models.Model):
    """Idempotency-protected, explicitly unverified factor report."""

    class Factor(models.TextChoices):
        PIN = "PIN", "PIN"
        FACE = "FACE", "Face"
        FINGERPRINT = "FINGERPRINT", "Fingerprint"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    attempt = models.ForeignKey(AuthAttempt, on_delete=models.CASCADE, related_name="events")
    event_id = models.UUIDField()
    factor = models.CharField(max_length=16, choices=Factor.choices)
    protocol_version = models.PositiveSmallIntegerField(default=1)
    evidence_class = models.CharField(max_length=32, default="CLIENT_ASSERTION")
    verified = models.BooleanField(default=False, editable=False)
    occurred_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "auth_attempt_event"
        constraints = [
            models.UniqueConstraint(fields=["attempt", "event_id"], name="uniq_attempt_event_id"),
            models.UniqueConstraint(fields=["attempt", "factor"], name="uniq_attempt_factor_report"),
            models.CheckConstraint(condition=models.Q(verified=False), name="attempt_event_never_verified"),
        ]
        ordering = ["occurred_at"]


class AuthAttemptCapability(models.Model):
    """One-time-flow bearer capability; it is not a JWT or general API token."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    attempt = models.OneToOneField(
        AuthAttempt,
        on_delete=models.CASCADE,
        related_name="preauth_capability",
    )
    token_digest = models.CharField(max_length=64, unique=True)
    expires_at = models.DateTimeField(db_index=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        db_table = "auth_attempt_capability"

