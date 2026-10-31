from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from rest_framework import serializers, status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from apps.audit.services import record_audit_event
from apps.authentication.serializers import PreAuthAttemptSerializer
from apps.authentication.serializers import SecureTokenRefreshSerializer
from apps.hardware_auth.capabilities import create_preauth_attempt
from apps.hardware_auth.serializers import AuthAttemptSerializer
from common.security import get_client_ip, normalize_username
from common.throttling import LoginIPThrottle, LoginUsernameThrottle

User = get_user_model()


class LoginView(TokenObtainPairView):
    """
    POST /api/v1/auth/token/

    Returns access + refresh tokens. Rate-limited by IP and username.
    Inactive accounts are rejected by Simple JWT via the default
    user_can_authenticate check.
    """

    throttle_classes = [LoginIPThrottle, LoginUsernameThrottle]

    def throttled(self, request, wait):
        username = normalize_username(request.data.get("username", ""))
        ip = get_client_ip(request)
        record_audit_event(
            event_type="LOGIN_LOCKED_OUT",
            result="FAILURE",
            safe_metadata={
                "ip": ip,
                "username": username[:64] if username else "unknown",
                "wait_seconds": wait,
            },
            strict=True,
        )
        super().throttled(request, wait)

    def post(self, request, *args, **kwargs):
        username = request.data.get("username", "")
        try:
            response = super().post(request, *args, **kwargs)
        except Exception:
            record_audit_event(
                event_type="LOGIN_FAILED",
                result="FAILURE",
                safe_metadata={"username": username[:64] if username else "unknown"},
                strict=True,
            )
            raise

        if response.status_code == 200:
            record_audit_event(
                event_type="LOGIN_SUCCESS",
                result="SUCCESS",
                safe_metadata={"username": username[:64]},
                strict=True,
            )
        else:
            record_audit_event(
                event_type="LOGIN_FAILED",
                result="FAILURE",
                safe_metadata={"username": username[:64] if username else "unknown"},
                strict=True,
            )
        return response


class OfflinePreAuthAttemptView(APIView):
    """Start a short-lived attempt without issuing ordinary JWT credentials."""

    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [LoginIPThrottle, LoginUsernameThrottle]

    def throttled(self, request, wait):
        record_audit_event(
            event_type="OFFLINE_PREAUTH_THROTTLED",
            result="DENIED",
            safe_metadata={"wait_seconds": wait},
            strict=True,
        )
        super().throttled(request, wait)

    def post(self, request):
        serializer = PreAuthAttemptSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        values = serializer.validated_data
        user = authenticate(
            request=request,
            username=values["username"],
            password=values["password"],
        )
        if user is None or not user.is_active:
            record_audit_event(
                "OFFLINE_PREAUTH_FAILED",
                "DENIED",
                safe_metadata={"reason": "credentials_unavailable"},
                strict=True,
            )
            return Response(
                {"error": {"code": "PREAUTH_UNAVAILABLE", "message": "Authentication could not be started."}},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        attempt, capability, error = create_preauth_attempt(
            user=user,
            device_id=values["device_id"],
        )
        if error:
            record_audit_event(
                "OFFLINE_PREAUTH_FAILED",
                "DENIED",
                actor_user=user,
                safe_metadata={"reason": "binding_unavailable"},
                strict=True,
            )
            return Response(
                {"error": {"code": "PREAUTH_UNAVAILABLE", "message": "Authentication could not be started."}},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        return Response(
            {
                "attempt": AuthAttemptSerializer(attempt).data,
                "attempt_capability": capability,
                "capability_header": "X-Auth-Attempt-Capability",
            },
            status=status.HTTP_201_CREATED,
        )


class TokenRefreshViewAudited(TokenRefreshView):
    """POST /api/v1/auth/token/refresh/ — refresh token rotation."""

    serializer_class = SecureTokenRefreshSerializer

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        if response.status_code == 200:
            record_audit_event(
                event_type="TOKEN_REFRESH",
                result="SUCCESS",
                safe_metadata={},
                strict=True,
            )
        return response


class LogoutView(APIView):
    """
    POST /api/v1/auth/logout/

    Blacklists the submitted refresh token. The client must also clear
    any in-memory access token and local session state.
    Optionally revokes all active access tokens if revoke_all=True is passed.
    """

    permission_classes = [IsAuthenticated]

    @transaction.atomic
    def post(self, request):
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response(
                {"error": {"code": "MISSING_REFRESH_TOKEN", "message": "Refresh token is required for logout."}},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            token = RefreshToken(refresh_token)
        except (TokenError, TypeError, ValueError):
            return Response(
                {"error": {"code": "INVALID_REFRESH_TOKEN", "message": "Refresh token is invalid."}},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if str(token.get(api_settings.USER_ID_CLAIM, "")) != str(request.user.pk):
            return Response(
                {"error": {"code": "INVALID_REFRESH_TOKEN", "message": "Refresh token is invalid."}},
                status=status.HTTP_400_BAD_REQUEST,
            )
        token.blacklist()

        # Optional full revocation across all sessions
        if request.data.get("revoke_all"):
            request.user.revoke_tokens()

        record_audit_event(
            event_type="LOGOUT",
            result="SUCCESS",
            actor_user=request.user,
            safe_metadata={"username": request.user.username},
            strict=True,
        )
        return Response({"detail": "Logged out successfully."}, status=status.HTTP_200_OK)


class ChangePasswordView(APIView):
    """POST /api/v1/auth/change-password/ — requires current password verification."""

    permission_classes = [IsAuthenticated]

    class _Serializer(serializers.Serializer):
        current_password = serializers.CharField(write_only=True)
        new_password = serializers.CharField(write_only=True, min_length=10)

        def validate_new_password(self, value):
            user = self.context["request"].user
            try:
                validate_password(value, user)
            except DjangoValidationError as exc:
                raise serializers.ValidationError(list(exc.messages)) from exc
            return value

    @transaction.atomic
    def post(self, request):
        serializer = self._Serializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)

        user = request.user
        if not user.check_password(serializer.validated_data["current_password"]):
            record_audit_event(
                event_type="PASSWORD_CHANGE_FAILED",
                result="FAILURE",
                actor_user=user,
                safe_metadata={"reason": "wrong_current_password"},
                strict=True,
            )
            return Response(
                {"error": {"code": "WRONG_PASSWORD", "message": "Current password is incorrect."}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.set_password(serializer.validated_data["new_password"])
        user.token_version += 1
        user.save(update_fields=["password", "token_version", "updated_at"])
        record_audit_event(
            event_type="PASSWORD_CHANGED",
            result="SUCCESS",
            actor_user=user,
            safe_metadata={},
            strict=True,
        )
        return Response({"detail": "Password changed successfully."}, status=status.HTTP_200_OK)
