"""
Security utilities: client IP resolution, username normalization, and secret sanitization.
"""

from django.conf import settings


def get_client_ip(request) -> str:
    """
    Safely resolve the client IP address.

    Security protection against IP spoofing:
    - Never blindly trust arbitrary X-Forwarded-For headers from untrusted clients.
    - Only parse X-Forwarded-For if USE_X_FORWARDED_FOR is explicitly enabled in settings.
    - When behind trusted reverse proxies (e.g. Render), takes the client IP using NUM_PROXIES.
    - Defaults to REMOTE_ADDR to prevent header-injection bypasses of rate limiters.
    """
    use_xff = getattr(settings, "USE_X_FORWARDED_FOR", False)
    if use_xff:
        xff = request.META.get("HTTP_X_FORWARDED_FOR")
        if xff:
            ips = [ip.strip() for ip in xff.split(",") if ip.strip()]
            num_proxies = getattr(settings, "NUM_PROXIES", 1)
            if len(ips) >= num_proxies:
                return ips[-num_proxies]
            elif ips:
                return ips[0]

    return request.META.get("REMOTE_ADDR", "127.0.0.1")


def normalize_username(username: str) -> str:
    """Normalize username for consistent lookup and throttling keys."""
    if not username:
        return ""
    return str(username).strip().lower()


# Blocklist of sensitive keys that must never appear in safe_metadata or audit payloads
FORBIDDEN_METADATA_KEYS = frozenset(
    {
        "password",
        "pass",
        "pin",
        "secret",
        "key",
        "private_key",
        "token",
        "access",
        "refresh",
        "authorization",
        "bearer",
        "biometric",
        "encoding",
        "credential",
    }
)


def sanitize_metadata(data: dict | None) -> dict:
    """Filter out any sensitive keys from metadata before logging."""
    if not data or not isinstance(data, dict):
        return {}

    sanitized = {}
    for key, value in data.items():
        lower_key = str(key).lower()
        # If key contains any forbidden word, skip it completely
        if any(forbidden in lower_key for forbidden in FORBIDDEN_METADATA_KEYS):
            continue
        # Truncate strings to avoid payload dump exploits
        if isinstance(value, str):
            sanitized[key] = value[:256]
        elif isinstance(value, (int, float, bool)) or value is None:
            sanitized[key] = value
        elif isinstance(value, dict):
            sanitized[key] = sanitize_metadata(value)
        elif isinstance(value, list):
            sanitized[key] = [
                str(item)[:128] for item in value[:20]
                if not any(f in str(item).lower() for f in FORBIDDEN_METADATA_KEYS)
            ]
        else:
            sanitized[key] = str(value)[:128]

    return sanitized
