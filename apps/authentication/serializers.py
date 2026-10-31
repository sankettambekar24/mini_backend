"""
Custom JWT serializers.

Security notes:
- Do NOT put passwords, biometric data, secret keys, or any sensitive
  information in JWT claims.
- Only include safe, non-sensitive identity claims.
"""

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken

from apps.authentication.authentication import validate_identity_claims

User = get_user_model()


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Extends the default token serializer to add safe role claim.
    No sensitive data (password, PIN, biometrics) in the token payload.
    """

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        # Safe claims only: role identifier, username, and token version for revocation.
        token["role"] = user.role
        token["username"] = user.username
        token["token_version"] = user.token_version
        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        # Add safe user info to the login response body.
        data["user"] = {
            "id": str(self.user.id),
            "username": self.user.username,
            "role": self.user.role,
        }
        return data


class PreAuthAttemptSerializer(serializers.Serializer):
    """Credentials used only to start a constrained attempt; never returns JWTs."""

    username = serializers.CharField(max_length=64, trim_whitespace=True)
    password = serializers.CharField(write_only=True, trim_whitespace=False)
    device_id = serializers.UUIDField()


class SecureTokenRefreshSerializer(TokenRefreshSerializer):
    """Reject stale or malformed identity claims before rotating a refresh token."""

    def validate(self, attrs):
        try:
            refresh = RefreshToken(attrs["refresh"])
            user_id = refresh.get(api_settings.USER_ID_CLAIM)
            if user_id is None:
                raise InvalidToken("Token contained no user identity.")
            user = User.objects.get(pk=user_id)
            if not user.is_active:
                raise InvalidToken("Token is invalid or expired.")
            validate_identity_claims(refresh, user)
        except (User.DoesNotExist, TokenError, ValueError, TypeError) as exc:
            raise InvalidToken("Token is invalid or expired.") from exc
        return super().validate(attrs)
