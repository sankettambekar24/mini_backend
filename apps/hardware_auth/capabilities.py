"""Issue and validate narrowly scoped pre-authentication capabilities."""

import hashlib
import secrets

from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed

from apps.audit.services import record_audit_event
from apps.devices.models import Device, DeviceStatus
from apps.hardware_auth.models import AuthAttempt, AuthAttemptCapability, AttemptStatus
from apps.hardware_auth.services import create_attempt


def _digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@transaction.atomic
def create_preauth_attempt(*, user, device_id):
    """Create an ordinary unverified AuthAttempt without minting a JWT."""
    attempt, error = create_attempt(user=user, device_id=device_id)
    if error:
        return None, None, error

    token = secrets.token_urlsafe(32)
    AuthAttemptCapability.objects.create(
        attempt=attempt,
        token_digest=_digest(token),
        expires_at=attempt.expires_at,
    )
    record_audit_event(
        "OFFLINE_PREAUTH_STARTED",
        "PENDING",
        actor_user=user,
        device=attempt.device,
        auth_attempt=attempt,
        safe_metadata={"capability_scope": "single_auth_attempt"},
        strict=True,
    )
    return attempt, token, None


def authenticate_attempt_capability(token, attempt_id):
    """Return the owning user for a valid, pending, single-attempt secret."""
    if not token or not attempt_id:
        raise AuthenticationFailed("Invalid attempt capability.")
    try:
        capability = AuthAttemptCapability.objects.select_related(
            "attempt__user", "attempt__device"
        ).get(
            attempt_id=attempt_id,
            token_digest=_digest(token),
            revoked_at__isnull=True,
            expires_at__gt=timezone.now(),
        )
    except AuthAttemptCapability.DoesNotExist as exc:
        raise AuthenticationFailed("Invalid or expired attempt capability.") from exc

    attempt = capability.attempt
    if (
        attempt.status not in (AttemptStatus.PENDING, AttemptStatus.FACTORS_PENDING)
        or attempt.is_expired()
        or not attempt.user_id
        or not attempt.user.is_active
        or not attempt.device_id
        or attempt.device.status != DeviceStatus.ACTIVE
        or attempt.device.owner_user_id != attempt.user_id
    ):
        raise AuthenticationFailed("Attempt capability is no longer valid.")
    return capability
