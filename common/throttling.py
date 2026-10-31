"""
Custom rate throttles for brute-force protection.

Scopes are configured in settings.REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']:
- auth_login_ip: rate per client IP (e.g. '10/minute')
- auth_login_user: rate per username + IP pair (e.g. '5/minute')
- auth_register: rate per IP for account registration (e.g. '3/minute')
"""

from rest_framework.throttling import SimpleRateThrottle
from common.security import get_client_ip, normalize_username


class LoginIPThrottle(SimpleRateThrottle):
    """Throttles login attempts based on client IP."""

    scope = "auth_login_ip"

    def get_rate(self):
        from rest_framework.settings import api_settings
        return api_settings.DEFAULT_THROTTLE_RATES.get(self.scope)

    def get_cache_key(self, request, view):
        if request.method != "POST":
            return None
        ip = get_client_ip(request)
        return self.cache_format % {"scope": self.scope, "ident": ip}


class LoginUsernameThrottle(SimpleRateThrottle):
    """
    Throttles login attempts targeting a specific username from a client IP.
    Prevents both single-source credential stuffing and brute-forcing.
    """

    scope = "auth_login_user"

    def get_rate(self):
        from rest_framework.settings import api_settings
        return api_settings.DEFAULT_THROTTLE_RATES.get(self.scope)

    def get_cache_key(self, request, view):
        if request.method != "POST":
            return None
        username = normalize_username(request.data.get("username", ""))
        if not username:
            return None
        ip = get_client_ip(request)
        return self.cache_format % {"scope": self.scope, "ident": f"{username}_{ip}"}


class LoginRateThrottle(LoginIPThrottle):
    """Backward-compatible alias for existing imports."""

    scope = "auth_login"


class RegisterRateThrottle(SimpleRateThrottle):
    """Throttles registration attempts by client IP."""

    scope = "auth_register"

    def get_cache_key(self, request, view):
        if request.method != "POST":
            return None
        ip = get_client_ip(request)
        return self.cache_format % {"scope": self.scope, "ident": ip}
