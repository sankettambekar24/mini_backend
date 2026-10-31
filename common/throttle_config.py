"""Validation for cache configuration used by security-critical throttles."""

from urllib.parse import urlsplit

from django.core.exceptions import ImproperlyConfigured


REDIS_CACHE_BACKEND = "django.core.cache.backends.redis.RedisCache"


def validate_production_throttle_cache(redis_url, caches):
    """Require a usable Redis URL and RedisCache; never accept local fallback."""
    redis_url = (redis_url or "").strip()
    if not redis_url:
        raise ImproperlyConfigured(
            "REDIS_URL is required in production for shared authentication throttling."
        )
    try:
        parsed = urlsplit(redis_url)
        port = parsed.port
    except ValueError as exc:
        raise ImproperlyConfigured("REDIS_URL must be a valid redis:// or rediss:// URL.") from exc
    if parsed.scheme not in {"redis", "rediss"} or not parsed.hostname or (
        port is not None and not 1 <= port <= 65535
    ):
        raise ImproperlyConfigured("REDIS_URL must be a valid redis:// or rediss:// URL.")
    if caches.get("default", {}).get("BACKEND") != REDIS_CACHE_BACKEND:
        raise ImproperlyConfigured("Production authentication throttling requires Django RedisCache.")
