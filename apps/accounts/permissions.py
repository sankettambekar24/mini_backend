from rest_framework.permissions import BasePermission

from apps.accounts.models import UserRole


class IsAdminRole(BasePermission):
    """Allow access only to users with the ADMIN role."""

    message = "Administrator access required."

    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and request.user.role == UserRole.ADMIN
        )


class IsOwnerOrAdmin(BasePermission):
    """Allow access to the resource owner or an admin."""

    def has_object_permission(self, request, view, obj):
        if not request.user or not request.user.is_authenticated:
            return False
        if request.user.role == UserRole.ADMIN:
            return True
        # obj must have an owner_user or user field
        owner = getattr(obj, "owner_user", None) or getattr(obj, "user", None)
        return owner == request.user
