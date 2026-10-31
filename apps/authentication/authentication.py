"""Secure JWT and attempt-capability authentication classes.

Secure JWT Authentication class.

Enhances DRF Simple JWT with:
- Token revocation verification via user.token_version
- Role claim consistency checks
- Inactive user immediate rejection
"""

from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import AuthenticationFailed
from rest_framework.authentication import BaseAuthentication

from apps.hardware_auth.capabilities import authenticate_attempt_capability
from apps.accounts.models import UserRole


def validate_identity_claims(token, user):
    token_version = token.get("token_version")
    token_role = token.get("role")
    if (
        isinstance(token_version, bool)
        or not isinstance(token_version, int)
        or token_version < 1
        or token_role not in UserRole.values
    ):
        raise AuthenticationFailed("Token is missing valid security claims.", code="invalid_token_claims")
    if token_version != user.token_version:
        raise AuthenticationFailed("Token has been revoked.", code="token_revoked")
    if token_role != user.role:
        raise AuthenticationFailed("Token role is no longer valid.", code="role_changed")


class SecureJWTAuthentication(JWTAuthentication):
    """
    Extends Simple JWT authentication to enforce instant token revocation:
    1. Validates that user.is_active is True.
    2. Validates that the user's current token_version matches the token's token_version claim.
       When password is changed or an admin revokes tokens, token_version is incremented,
       which immediately invalidates all previously issued stateless access tokens.
    3. Validates that the user's role matches the role claim embedded in the token.
       If role is changed (e.g. admin promotes/demotes a user), the token is invalidated.
    """

    def authenticate(self, request):
        header = self.get_header(request)
        if header is None:
            return None

        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None

        validated_token = self.get_validated_token(raw_token)
        user = self.get_user(validated_token)

        # Check account active status
        if not user.is_active:
            raise AuthenticationFailed("User account is inactive or disabled.", code="user_inactive")

        validate_identity_claims(validated_token, user)

        return (user, validated_token)


class AttemptCapabilityAuthentication(BaseAuthentication):
    """Authenticate only a capability bound to the URL's one AuthAttempt."""

    header_name = "HTTP_X_AUTH_ATTEMPT_CAPABILITY"

    def authenticate(self, request):
        token = request.META.get(self.header_name)
        if not token:
            return None
        parser_context = getattr(request, "parser_context", None) or {}
        attempt_id = (parser_context.get("kwargs") or {}).get("id")
        if not attempt_id:
            raise AuthenticationFailed("Attempt capability is not valid for this route.")
        capability = authenticate_attempt_capability(token, attempt_id)
        return capability.attempt.user, capability
