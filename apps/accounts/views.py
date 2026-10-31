from django.contrib.auth import get_user_model
from django.db import transaction
from rest_framework import generics, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.models import AdminBootstrapLock, UserRole
from apps.accounts.permissions import IsAdminRole
from apps.accounts.serializers import (
    AdminRoleChangeSerializer,
    AdminUserCreateSerializer,
    AdminUserListSerializer,
    AdminUserUpdateSerializer,
    UserProfileSerializer,
    UserRegistrationSerializer,
)
from apps.audit.services import record_audit_event
from common.throttling import RegisterRateThrottle

User = get_user_model()


def _lock_admin_policy():
    """Serialize all API mutations that can create/remove the designated admin."""
    AdminBootstrapLock.objects.get_or_create(key="singleton")
    AdminBootstrapLock.objects.select_for_update().get(key="singleton")


class RegisterView(generics.CreateAPIView):
    """
    POST /api/v1/auth/register/

    Creates a USER-role account only. Rate-limited.
    An ADMIN cannot be created through self-registration.
    """

    serializer_class = UserRegistrationSerializer
    permission_classes = [AllowAny]
    throttle_classes = [RegisterRateThrottle]

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        record_audit_event(
            event_type="USER_REGISTERED",
            result="SUCCESS",
            actor_user=None,
            safe_metadata={"username": user.username, "role": user.role},
            strict=True,
        )
        return Response(
            {
                "id": str(user.id),
                "username": user.username,
                "role": user.role,
            },
            status=status.HTTP_201_CREATED,
        )


class MeView(generics.RetrieveAPIView):
    """GET /api/v1/auth/me/ — current user's safe profile."""

    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user


# ---------------------------------------------------------------------------
# Admin user management
# ---------------------------------------------------------------------------


class AdminUserListCreateView(generics.ListCreateAPIView):
    """GET/POST /api/v1/admin/users/ — admin-only."""

    permission_classes = [IsAuthenticated, IsAdminRole]

    def get_serializer_class(self):
        if self.request.method == "POST":
            return AdminUserCreateSerializer
        return AdminUserListSerializer

    def get_queryset(self):
        return User.objects.all().order_by("created_at")

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        _lock_admin_policy()
        return super().create(request, *args, **kwargs)

    def perform_create(self, serializer):
        user = serializer.save()
        record_audit_event(
            event_type="ADMIN_USER_CREATED",
            result="SUCCESS",
            actor_user=self.request.user,
            safe_metadata={"created_username": user.username, "role": user.role},
            strict=True,
        )


class AdminUserDetailView(generics.RetrieveUpdateAPIView):
    """PATCH /api/v1/admin/users/{user_id}/ — admin-only."""

    permission_classes = [IsAuthenticated, IsAdminRole]
    serializer_class = AdminUserUpdateSerializer
    queryset = User.objects.all()
    lookup_field = "id"

    @transaction.atomic
    def update(self, request, *args, **kwargs):
        _lock_admin_policy()
        target = User.objects.select_for_update().filter(id=kwargs.get("id")).first()
        if (
            target
            and target.role == UserRole.ADMIN
            and request.data.get("is_active") is False
            and User.objects.filter(role=UserRole.ADMIN, is_active=True).count() <= 1
        ):
            return Response(
                {"error": {"code": "LAST_ADMIN_REQUIRED", "message": "The designated administrator cannot be deactivated."}},
                status=status.HTTP_409_CONFLICT,
            )
        return super().update(request, *args, **kwargs)

    def perform_update(self, serializer):
        old_active = self.get_object().is_active
        user = serializer.save()
        if old_active and not user.is_active:
            user.revoke_tokens()
            record_audit_event(
                event_type="USER_DEACTIVATED",
                result="SUCCESS",
                actor_user=self.request.user,
                safe_metadata={"target_user_id": str(user.id), "target_username": user.username},
                strict=True,
            )
        elif not old_active and user.is_active:
            record_audit_event(
                event_type="USER_ACTIVATED",
                result="SUCCESS",
                actor_user=self.request.user,
                safe_metadata={"target_user_id": str(user.id), "target_username": user.username},
                strict=True,
            )
        record_audit_event(
            event_type="ADMIN_USER_UPDATED",
            result="SUCCESS",
            actor_user=self.request.user,
            safe_metadata={"target_user_id": str(user.id), "is_active": user.is_active},
            strict=True,
        )


class AdminUserDisableView(APIView):
    """POST /api/v1/admin/users/{user_id}/disable/ — admin-only, audited."""

    permission_classes = [IsAuthenticated, IsAdminRole]

    @transaction.atomic
    def post(self, request, id):
        _lock_admin_policy()
        try:
            user = User.objects.select_for_update().get(id=id)
        except User.DoesNotExist:
            return Response({"error": {"code": "NOT_FOUND", "message": "User not found."}}, status=404)

        if str(user.id) == str(request.user.id):
            return Response(
                {"error": {"code": "SELF_DISABLE_FORBIDDEN", "message": "An admin cannot disable their own account."}},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if user.role == UserRole.ADMIN and user.is_active and User.objects.filter(
            role=UserRole.ADMIN, is_active=True
        ).count() <= 1:
            return Response(
                {"error": {"code": "LAST_ADMIN_REQUIRED", "message": "The designated administrator cannot be deactivated."}},
                status=status.HTTP_409_CONFLICT,
            )
        user.is_active = False
        user.token_version += 1
        user.save(update_fields=["is_active", "token_version", "updated_at"])
        record_audit_event(
            event_type="USER_DISABLED",
            result="SUCCESS",
            actor_user=request.user,
            safe_metadata={"target_user_id": str(user.id), "target_username": user.username},
            strict=True,
        )
        record_audit_event(
            event_type="USER_DEACTIVATED",
            result="SUCCESS",
            actor_user=request.user,
            safe_metadata={"target_user_id": str(user.id), "target_username": user.username},
            strict=True,
        )
        return Response({"id": str(user.id), "is_active": False}, status=status.HTTP_200_OK)


class AdminUserRoleView(APIView):
    """POST /api/v1/admin/users/{user_id}/role/ — admin-only, audited."""

    permission_classes = [IsAuthenticated, IsAdminRole]

    @transaction.atomic
    def post(self, request, id):
        _lock_admin_policy()
        serializer = AdminRoleChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        new_role = serializer.validated_data["role"]

        try:
            user = User.objects.select_for_update().get(id=id)
        except User.DoesNotExist:
            return Response({"error": {"code": "NOT_FOUND", "message": "User not found."}}, status=404)

        old_role = user.role
        if old_role != UserRole.ADMIN and new_role == UserRole.ADMIN and User.objects.filter(
            role=UserRole.ADMIN
        ).exists():
            return Response(
                {"error": {"code": "DESIGNATED_ADMIN_EXISTS", "message": "The designated administrator already exists."}},
                status=status.HTTP_409_CONFLICT,
            )
        if old_role == UserRole.ADMIN and new_role != UserRole.ADMIN and User.objects.filter(
            role=UserRole.ADMIN, is_active=True
        ).count() <= 1:
            return Response(
                {"error": {"code": "LAST_ADMIN_REQUIRED", "message": "The designated administrator cannot be demoted."}},
                status=status.HTTP_409_CONFLICT,
            )
        user.role = new_role
        if new_role == UserRole.ADMIN:
            user.is_staff = True
            user.is_superuser = True
        else:
            user.is_staff = False
            user.is_superuser = False
        user.token_version += 1
        user.save(update_fields=["role", "is_staff", "is_superuser", "token_version", "updated_at"])
        record_audit_event(
            event_type="USER_ROLE_CHANGED",
            result="SUCCESS",
            actor_user=request.user,
            safe_metadata={
                "target_user_id": str(user.id),
                "old_role": old_role,
                "new_role": new_role,
            },
            strict=True,
        )
        return Response({"id": str(user.id), "role": user.role}, status=status.HTTP_200_OK)
