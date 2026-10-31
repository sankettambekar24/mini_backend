"""Atomic device registry operations."""

from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import NotFound, ValidationError

from apps.audit.services import record_audit_event
from apps.devices.models import Device, DeviceStatus


ALLOWED_TRANSITIONS = {
    DeviceStatus.PENDING: {DeviceStatus.ACTIVE, DeviceStatus.REVOKED, DeviceStatus.LOST},
    DeviceStatus.ACTIVE: {DeviceStatus.REVOKED, DeviceStatus.LOST},
    DeviceStatus.LOST: {DeviceStatus.REVOKED},
    DeviceStatus.REVOKED: set(),
}


@transaction.atomic
def change_device_status(device_id, new_status, actor):
    try:
        device = Device.objects.select_for_update().get(id=device_id)
    except Device.DoesNotExist as exc:
        raise NotFound("Device not found.") from exc
    if new_status not in ALLOWED_TRANSITIONS[device.status]:
        raise ValidationError({"code": "INVALID_DEVICE_TRANSITION", "detail": f"Cannot move {device.status} to {new_status}."})
    old_status = device.status
    device.status = new_status
    device.revoked_at = timezone.now() if new_status == DeviceStatus.REVOKED else None
    device.save(update_fields=["status", "revoked_at", "updated_at"])
    record_audit_event(
        "DEVICE_STATUS_CHANGED", "SUCCESS", actor_user=actor, device=device,
        safe_metadata={"from": old_status, "to": new_status}, strict=True,
    )
    return device


@transaction.atomic
def assign_device(device_id, owner, actor):
    try:
        device = Device.objects.select_for_update().get(id=device_id)
    except Device.DoesNotExist as exc:
        raise NotFound("Device not found.") from exc
    if device.status != DeviceStatus.PENDING:
        raise ValidationError({"code": "DEVICE_ASSIGNMENT_LOCKED", "detail": "Ownership can only be assigned while the device is pending."})
    device.owner_user = owner
    device.save(update_fields=["owner_user", "updated_at"])
    record_audit_event(
        "DEVICE_ASSIGNED", "SUCCESS", actor_user=actor, device=device,
        safe_metadata={"owner_user_id": str(owner.id) if owner else None}, strict=True,
    )
    return device
