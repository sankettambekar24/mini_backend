"""Atomic authentication-attempt transaction operations.

Factor reports are telemetry only. This backend currently has no validated
PIN, host-face, or authenticated STM32 evidence verifier, so no report can
mark a factor verified or move an attempt to SUCCEEDED.
"""

from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from apps.audit.services import record_audit_event
from apps.devices.models import Device, DeviceStatus
from apps.hardware_auth.models import AttemptStatus, AuthAttempt, AuthAttemptEvent

REQUIRED_FACTORS = ["PIN", "FACE", "FINGERPRINT"]
EVIDENCE_CLASSES = {
    "PIN": "CLIENT_ASSERTION",
    "FACE": "HOST_ASSERTION",
    "FINGERPRINT": "UNAUTHENTICATED_SERIAL",
}
ATTEMPT_TTL_SECONDS = 300


@transaction.atomic
def create_attempt(*, user, device_id):
    if not user.is_active:
        return None, "USER_INACTIVE"
    try:
        device = Device.objects.select_for_update().get(id=device_id)
    except Device.DoesNotExist:
        return None, "DEVICE_NOT_FOUND"
    if device.owner_user_id != user.id:
        return None, "DEVICE_USER_MISMATCH"
    if device.status != DeviceStatus.ACTIVE:
        return None, "DEVICE_INACTIVE"
    now = timezone.now()
    attempt = AuthAttempt.objects.create(
        user=user,
        device=device,
        status=AttemptStatus.PENDING,
        required_factors=REQUIRED_FACTORS,
        completed_factors=[],
        created_at=now,
        expires_at=now + timedelta(seconds=ATTEMPT_TTL_SECONDS),
    )
    record_audit_event(
        "AUTH_ATTEMPT_CREATED", "PENDING", actor_user=user, device=device,
        auth_attempt=attempt, safe_metadata={"required_factors": REQUIRED_FACTORS}, strict=True,
    )
    return attempt, None


@transaction.atomic
def report_factor(*, attempt_id, actor, device_id, event_id, factor, protocol_version):
    try:
        # Only lock AuthAttempt: nullable user/device joins cannot be included
        # in PostgreSQL's FOR UPDATE lock target.
        attempt = AuthAttempt.objects.select_for_update(of=("self",)).select_related("device", "user").get(id=attempt_id)
    except AuthAttempt.DoesNotExist:
        return None, None, "ATTEMPT_NOT_FOUND"
    if attempt.user_id != actor.id:
        record_audit_event("AUTH_ATTEMPT_EVENT_REJECTED", "DENIED", actor_user=actor,
                           device=attempt.device, auth_attempt=attempt,
                           safe_metadata={"reason": "user_mismatch"}, strict=True)
        return attempt, None, "ATTEMPT_USER_MISMATCH"
    if str(attempt.device_id) != str(device_id):
        record_audit_event("AUTH_ATTEMPT_EVENT_REJECTED", "DENIED", actor_user=actor,
                           device=attempt.device, auth_attempt=attempt,
                           safe_metadata={"reason": "device_mismatch"}, strict=True)
        return attempt, None, "ATTEMPT_DEVICE_MISMATCH"
    if attempt.status not in (AttemptStatus.PENDING, AttemptStatus.FACTORS_PENDING):
        return attempt, None, "INVALID_ATTEMPT_STATE"

    # Lock the device after the attempt, matching all attempt mutation paths.
    device = Device.objects.select_for_update().get(id=attempt.device_id)
    if not actor.is_active or not attempt.user.is_active:
        return attempt, None, "USER_INACTIVE"
    if device.status != DeviceStatus.ACTIVE or device.owner_user_id != attempt.user_id:
        attempt.status = AttemptStatus.FAILED
        attempt.failure_code = "DEVICE_INACTIVE"
        attempt.completed_at = timezone.now()
        attempt.save(update_fields=["status", "failure_code", "completed_at"])
        record_audit_event(
            "AUTH_ATTEMPT_FAILED", "FAILURE", actor_user=actor, device=device,
            auth_attempt=attempt, safe_metadata={"reason": "device_inactive"}, strict=True,
        )
        return attempt, None, "DEVICE_INACTIVE"
    if attempt.is_expired():
        attempt.status = AttemptStatus.EXPIRED
        attempt.failure_code = "EXPIRED"
        attempt.completed_at = timezone.now()
        attempt.save(update_fields=["status", "failure_code", "completed_at"])
        record_audit_event(
            "AUTH_ATTEMPT_EXPIRED", "EXPIRED", actor_user=actor, device=device,
            auth_attempt=attempt, safe_metadata={}, strict=True,
        )
        return attempt, None, "ATTEMPT_EXPIRED"
    if factor not in REQUIRED_FACTORS:
        return attempt, None, "INVALID_FACTOR"
    if AuthAttemptEvent.objects.filter(attempt=attempt, event_id=event_id).exists():
        record_audit_event("AUTH_ATTEMPT_EVENT_REJECTED", "DENIED", actor_user=actor,
                           device=device, auth_attempt=attempt,
                           safe_metadata={"reason": "replayed_event"}, strict=True)
        return attempt, None, "REPLAYED_EVENT"
    if AuthAttemptEvent.objects.filter(attempt=attempt, factor=factor).exists():
        record_audit_event("AUTH_ATTEMPT_EVENT_REJECTED", "DENIED", actor_user=actor,
                           device=device, auth_attempt=attempt,
                           safe_metadata={"reason": "duplicate_factor"}, strict=True)
        return attempt, None, "DUPLICATE_FACTOR"

    event = AuthAttemptEvent.objects.create(
        attempt=attempt,
        event_id=event_id,
        factor=factor,
        protocol_version=protocol_version,
        evidence_class=EVIDENCE_CLASSES[factor],
        verified=False,
    )
    attempt.status = AttemptStatus.FACTORS_PENDING
    attempt.save(update_fields=["status"])
    record_audit_event(
        "AUTH_FACTOR_REPORTED", "UNVERIFIED", actor_user=actor, device=device,
        auth_attempt=attempt,
        safe_metadata={"factor": factor, "evidence_class": event.evidence_class,
                       "protocol_version": protocol_version},
        strict=True,
    )
    return attempt, event, None


@transaction.atomic
def cancel_attempt(*, attempt_id, actor, device_id):
    try:
        attempt = AuthAttempt.objects.select_for_update(of=("self",)).select_related("device").get(id=attempt_id)
    except AuthAttempt.DoesNotExist:
        return None, "ATTEMPT_NOT_FOUND"
    if attempt.user_id != actor.id or str(attempt.device_id) != str(device_id):
        return attempt, "ATTEMPT_BINDING_MISMATCH"
    if attempt.status not in (AttemptStatus.PENDING, AttemptStatus.FACTORS_PENDING):
        return attempt, "INVALID_ATTEMPT_STATE"
    if attempt.is_expired():
        attempt.status = AttemptStatus.EXPIRED
        attempt.failure_code = "EXPIRED"
        attempt.completed_at = timezone.now()
        attempt.save(update_fields=["status", "failure_code", "completed_at"])
        record_audit_event(
            "AUTH_ATTEMPT_EXPIRED", "EXPIRED", actor_user=actor, device=attempt.device,
            auth_attempt=attempt, safe_metadata={}, strict=True,
        )
        return attempt, "ATTEMPT_EXPIRED"
    attempt.status = AttemptStatus.CANCELLED
    attempt.failure_code = "CANCELLED"
    attempt.completed_at = timezone.now()
    attempt.save(update_fields=["status", "failure_code", "completed_at"])
    record_audit_event(
        "AUTH_ATTEMPT_CANCELLED", "CANCELLED", actor_user=actor, device=attempt.device,
        auth_attempt=attempt, safe_metadata={}, strict=True,
    )
    return attempt, None


@transaction.atomic
def complete_attempt(*, attempt_id, actor, device_id):
    try:
        attempt = AuthAttempt.objects.select_for_update(of=("self",)).select_related("device", "user").get(id=attempt_id)
    except AuthAttempt.DoesNotExist:
        return None, "ATTEMPT_NOT_FOUND"
    if attempt.user_id != actor.id or str(attempt.device_id) != str(device_id):
        return attempt, "ATTEMPT_BINDING_MISMATCH"
    if attempt.status not in (AttemptStatus.PENDING, AttemptStatus.FACTORS_PENDING):
        return attempt, "INVALID_ATTEMPT_STATE"
    device = Device.objects.select_for_update().get(id=attempt.device_id)
    if not actor.is_active or not attempt.user.is_active:
        return attempt, "USER_INACTIVE"
    if device.status != DeviceStatus.ACTIVE or device.owner_user_id != attempt.user_id:
        attempt.status = AttemptStatus.FAILED
        attempt.failure_code = "DEVICE_INACTIVE"
        attempt.completed_at = timezone.now()
        attempt.save(update_fields=["status", "failure_code", "completed_at"])
        record_audit_event(
            "AUTH_ATTEMPT_FAILED", "FAILURE", actor_user=actor, device=device,
            auth_attempt=attempt, safe_metadata={"reason": "device_inactive"}, strict=True,
        )
        return attempt, "DEVICE_INACTIVE"
    if attempt.is_expired():
        attempt.status = AttemptStatus.EXPIRED
        attempt.failure_code = "EXPIRED"
        attempt.completed_at = timezone.now()
        attempt.save(update_fields=["status", "failure_code", "completed_at"])
        record_audit_event(
            "AUTH_ATTEMPT_EXPIRED", "EXPIRED", actor_user=actor, device=device,
            auth_attempt=attempt, safe_metadata={}, strict=True,
        )
        return attempt, "ATTEMPT_EXPIRED"
    # The reported events are intentionally never interpreted as factor proof.
    record_audit_event(
        "AUTH_ATTEMPT_COMPLETION_BLOCKED", "DENIED", actor_user=actor, device=device,
        auth_attempt=attempt, safe_metadata={"reason": "factor_verification_unavailable"}, strict=True,
    )
    return attempt, "FACTOR_VERIFICATION_UNAVAILABLE"
