"""
Production settings for Render deployment.
All secrets MUST come from Render's environment variable/secret configuration.
Do NOT hardcode any value here. Do NOT commit .env files.
"""

from .base import *  # noqa: F401,F403

import os
from urllib.parse import urlsplit

from django.core.exceptions import ImproperlyConfigured
from common.throttle_config import validate_production_throttle_cache

DEBUG = False

# Never let a production service quietly use an ephemeral SQLite database.
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
if not DATABASE_URL:
    raise ImproperlyConfigured("DATABASE_URL is required in production and must point to PostgreSQL.")
try:
    database_scheme = urlsplit(DATABASE_URL).scheme.lower()
except ValueError as exc:
    raise ImproperlyConfigured("DATABASE_URL must be a valid PostgreSQL URL.") from exc
if database_scheme not in {"postgres", "postgresql", "postgresql+psycopg2"}:
    raise ImproperlyConfigured("Production requires PostgreSQL; SQLite and other database engines are not supported.")
if DATABASES["default"]["ENGINE"] != "django.db.backends.postgresql":
    raise ImproperlyConfigured("Production database configuration did not resolve to PostgreSQL.")
if os.environ.get("DB_SSL_REQUIRE", "true").strip().lower() != "true":
    raise ImproperlyConfigured("DB_SSL_REQUIRE must remain true in production.")

# Neon pooled URLs use PgBouncer transaction pooling. Django's default
# server-side cursors are connection/session scoped, so disable them for the
# runtime connection. Migrations and administrative tooling use a direct URL.
DATABASES["default"]["DISABLE_SERVER_SIDE_CURSORS"] = True
DATABASES["default"]["CONN_HEALTH_CHECKS"] = True

# Production credentials are explicit and independently rotatable.
if len(SECRET_KEY) < 50:
    raise ImproperlyConfigured("DJANGO_SECRET_KEY must contain at least 50 characters in production.")
JWT_SIGNING_KEY = os.environ.get("JWT_SIGNING_KEY", "")
if len(JWT_SIGNING_KEY) < 50 or JWT_SIGNING_KEY == SECRET_KEY:
    raise ImproperlyConfigured(
        "JWT_SIGNING_KEY must be a separate environment secret of at least 50 characters in production."
    )
SIMPLE_JWT = {**SIMPLE_JWT, "SIGNING_KEY": JWT_SIGNING_KEY}

# Security-critical DRF throttles use Django's default cache. Production must
# use a shared Redis cache; LocMemCache silently splits counters per worker.
validate_production_throttle_cache(os.environ.get("REDIS_URL"), CACHES)

# Render injects the service hostname; add it automatically.
RENDER_EXTERNAL_HOSTNAME = os.environ.get("RENDER_EXTERNAL_HOSTNAME")
if RENDER_EXTERNAL_HOSTNAME:
    ALLOWED_HOSTS.append(RENDER_EXTERNAL_HOSTNAME)
ALLOWED_HOSTS = list(dict.fromkeys(ALLOWED_HOSTS))
if not ALLOWED_HOSTS or "*" in ALLOWED_HOSTS:
    raise ImproperlyConfigured(
        "Set DJANGO_ALLOWED_HOSTS or deploy on Render with RENDER_EXTERNAL_HOSTNAME; wildcard hosts are forbidden."
    )

# ---------------------------------------------------------------------------
# HTTPS / proxy configuration for Render
# Render terminates TLS at its edge; Django sees HTTP from the proxy.
# ---------------------------------------------------------------------------
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
USE_X_FORWARDED_FOR = True
NUM_PROXIES = 1
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# ---------------------------------------------------------------------------
# Trusted origins for CSRF (required when behind a proxy)
# ---------------------------------------------------------------------------
CSRF_TRUSTED_ORIGINS = [
    o.strip()
    for o in os.environ.get("CSRF_TRUSTED_ORIGINS", "").split(",")
    if o.strip()
]
if any(not origin.startswith("https://") for origin in CSRF_TRUSTED_ORIGINS):
    raise ImproperlyConfigured("Production CSRF_TRUSTED_ORIGINS entries must use HTTPS.")
if any(not origin.startswith("https://") for origin in CORS_ALLOWED_ORIGINS):
    raise ImproperlyConfigured("Production CORS_ALLOWED_ORIGINS entries must use HTTPS.")
# The supported HSS client is a native bearer-token app, not a cross-origin
# browser using cookies. Keep credentialed CORS disabled in production.
CORS_ALLOW_CREDENTIALS = False

# ---------------------------------------------------------------------------
# Production logging — structured, no sensitive data
# ---------------------------------------------------------------------------
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json_safe": {
            "format": "[{levelname}] {asctime} {name} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json_safe",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "WARNING",
    },
    "loggers": {
        "django.security": {
            "handlers": ["console"],
            "level": "ERROR",
            "propagate": False,
        },
        "secure_backend": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
    },
}
