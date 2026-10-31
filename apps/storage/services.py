"""Default-deny metadata and grant authorization services.

No service in this module reads or writes physical SD bytes. File IDs are the
stable StoredFileMetadata UUIDs; the legacy path-based API is not consulted.
"""

from uuid import UUID

from django.db import transaction
from django.db.models import Q
from django.http import Http404
from django.utils import timezone

from apps.accounts.models import UserRole
from apps.audit.services import record_audit_event
from apps.permissions.models import PermissionGrant, PermissionType
from apps.storage.models import StoredFileMetadata


class FileAuthorizationError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _active_grants(user, permission, *, now=None):
    now = now or timezone.now()
    return PermissionGrant.objects.filter(
        subject_user=user,
        permission=permission,
        revoked_at__isnull=True,
    ).filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))


def visible_files(user):
    files = StoredFileMetadata.objects.filter(deleted_at__isnull=True).select_related("owner_user")
    if user.role == UserRole.ADMIN:
        return files
    listed_ids = []
    for resource_id in _active_grants(user, PermissionType.LIST).values_list("resource_id", flat=True):
        try:
            parsed_id = UUID(resource_id)
        except (ValueError, TypeError, AttributeError):
            continue
        if str(parsed_id) == resource_id.lower():
            listed_ids.append(parsed_id)
    return files.filter(Q(owner_user=user) | Q(id__in=listed_ids)).distinct()


def get_file_for_metadata(*, file_id, user):
    try:
        file_record = StoredFileMetadata.objects.get(id=file_id, deleted_at__isnull=True)
    except (StoredFileMetadata.DoesNotExist, ValueError, TypeError) as exc:
        raise Http404 from exc
    if user.role == UserRole.ADMIN or file_record.owner_user_id == user.id:
        return file_record
    if _active_grants(user, PermissionType.READ).filter(resource_id=str(file_record.id)).exists():
        return file_record
    raise Http404


def get_file_for_content(*, file_id, user):
    """Authorize the future content boundary, which remains unavailable here."""
    try:
        file_record = StoredFileMetadata.objects.get(id=file_id, deleted_at__isnull=True)
    except (StoredFileMetadata.DoesNotExist, ValueError, TypeError) as exc:
        raise Http404 from exc
    if file_record.owner_user_id == user.id:
        return file_record
    if _active_grants(user, PermissionType.READ).filter(resource_id=str(file_record.id)).exists():
        return file_record
    # Administrator role grants metadata administration, not content access.
    raise Http404


def get_file_for_grant_management(*, file_id, user, lock=False):
    queryset = StoredFileMetadata.objects
    if lock:
        queryset = queryset.select_for_update()
    try:
        file_record = queryset.get(id=file_id, deleted_at__isnull=True)
    except (StoredFileMetadata.DoesNotExist, ValueError, TypeError) as exc:
        raise Http404 from exc
    if user.role != UserRole.ADMIN and file_record.owner_user_id != user.id:
        raise Http404
    return file_record


@transaction.atomic
def register_metadata(*, actor, owner_user, display_name):
    if actor.role != UserRole.ADMIN:
        raise FileAuthorizationError("ADMIN_REQUIRED")
    if not owner_user.is_active:
        raise FileAuthorizationError("FILE_OWNER_INACTIVE")
    file_record = StoredFileMetadata.objects.create(
        owner_user=owner_user,
        display_name=display_name,
        size_bytes=0,
        encryption_format_version=0,
    )
    record_audit_event(
        "FILE_METADATA_REGISTERED", "SUCCESS", actor_user=actor,
        safe_metadata={"file_id": str(file_record.id), "owner_user_id": str(owner_user.id)},
        strict=True,
    )
    return file_record


@transaction.atomic
def create_grant(*, file_id, actor, subject_user, permission, expires_at=None):
    file_record = get_file_for_grant_management(file_id=file_id, user=actor, lock=True)
    if permission not in (PermissionType.LIST, PermissionType.READ):
        raise FileAuthorizationError("GRANT_PERMISSION_UNAVAILABLE")
    if not subject_user.is_active:
        raise FileAuthorizationError("GRANT_SUBJECT_INACTIVE")
    now = timezone.now()
    if expires_at is not None and expires_at <= now:
        raise FileAuthorizationError("GRANT_EXPIRY_NOT_FUTURE")

    resource_id = str(file_record.id)
    grant, created = PermissionGrant.objects.get_or_create(
        subject_user=subject_user,
        resource_id=resource_id,
        permission=permission,
        defaults={
            "granted_by": actor,
            "expires_at": expires_at,
        },
    )
    if not created:
        if grant.is_active():
            raise FileAuthorizationError("GRANT_ALREADY_ACTIVE")
        grant.granted_by = actor
        grant.expires_at = expires_at
        grant.revoked_at = None
        grant.created_at = now
        grant.save(update_fields=["granted_by", "expires_at", "revoked_at", "created_at"])

    record_audit_event(
        "FILE_GRANT_CREATED", "SUCCESS", actor_user=actor,
        safe_metadata={
            "file_id": resource_id,
            "grant_id": str(grant.id),
            "subject_user_id": str(subject_user.id),
            "permission": permission,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "reactivated": not created,
        },
        strict=True,
    )
    return grant


@transaction.atomic
def revoke_grant(*, file_id, grant_id, actor):
    file_record = get_file_for_grant_management(file_id=file_id, user=actor, lock=True)
    try:
        grant = PermissionGrant.objects.select_for_update().get(
            id=grant_id,
            resource_id=str(file_record.id),
        )
    except PermissionGrant.DoesNotExist as exc:
        raise Http404 from exc
    if grant.revoked_at is not None:
        raise FileAuthorizationError("GRANT_ALREADY_REVOKED")

    grant.revoked_at = timezone.now()
    grant.save(update_fields=["revoked_at"])
    record_audit_event(
        "FILE_GRANT_REVOKED", "SUCCESS", actor_user=actor,
        safe_metadata={
            "file_id": str(file_record.id),
            "grant_id": str(grant.id),
            "subject_user_id": str(grant.subject_user_id),
            "permission": grant.permission,
        },
        strict=True,
    )
    return grant
