"""Audit event service — append-only security event recording.

Security rules:
- Never log passwords, PINs, tokens, private keys, raw biometric data, or
  encryption keys.
- Keep safe_metadata allowlisted; avoid arbitrary request-body dumps.
- Records are append-only; never update or delete audit events.
"""

import uuid
import logging
from django.utils import timezone
from common.security import sanitize_metadata

logger = logging.getLogger("secure_backend.audit")


def record_audit_event(
    event_type: str,
    result: str,
    actor_user=None,
    device=None,
    auth_attempt=None,
    safe_metadata: dict | None = None,
    correlation_id: str | None = None,
    strict: bool = True,
    using: str | None = None,
):
    """
    Record a security event. Imports the model lazily to avoid circular imports
    at module load time.

    Parameters
    ----------
    event_type : str   Enumerated event type (e.g. "LOGIN_SUCCESS").
    result     : str   Enumerated result (e.g. "SUCCESS", "FAILURE").
    actor_user : User | None   Authenticated actor; may be None for pre-auth events.
    device     : Device | None
    auth_attempt : AuthAttempt | None
    safe_metadata : dict | None  Allowlisted metadata only; no secrets.
    correlation_id : str | None  Request correlation ID if available.
    """
    from apps.audit.models import AuditEvent  # lazy import

    try:
        device_str = str(device.id) if hasattr(device, "id") else str(device or "")
        attempt_str = str(auth_attempt.id) if hasattr(auth_attempt, "id") else str(auth_attempt or "")
        clean_metadata = sanitize_metadata(safe_metadata)
        audit_manager = AuditEvent.objects.using(using) if using else AuditEvent.objects
        audit_manager.create(
            id=uuid.uuid4(),
            occurred_at=timezone.now(),
            actor_user=actor_user,
            device_ref=device_str,
            auth_attempt_ref=attempt_str,
            event_type=event_type[:64],
            result=result[:32],
            correlation_id=correlation_id or "",
            safe_metadata=clean_metadata,
        )
    except Exception as exc:
        if strict:
            raise
        # Callers must explicitly opt in to best-effort, non-critical telemetry.
        logger.error("Audit event recording failed: %s (event_type=%s)", exc, event_type)
