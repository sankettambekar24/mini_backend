"""
Base Django settings for Hybrid Secure Storage System backend.

Environment-specific overrides live in local.py and production.py.
Never put secrets in this file. All secrets must come from environment variables.
"""

import os
from datetime import timedelta
from pathlib import Path

import dj_database_url

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent.parent  # backend/

# ---------------------------------------------------------------------------
# Security — all secret/environment values must be set externally
# ---------------------------------------------------------------------------
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]

# Offline-policy signing is deliberately unavailable by default. The Phase A
# service also has a code-owned prerequisite gate that prevents this switch
# from enabling issuance before device proof, file grants, trusted expiry, and
# verified authentication evidence exist.
OFFLINE_POLICY_ISSUANCE_ENABLED = os.environ.get("OFFLINE_POLICY_ISSUANCE_ENABLED", "false").lower() == "true"
OFFLINE_POLICY_SIGNING_KEY_ID = os.environ.get("OFFLINE_POLICY_SIGNING_KEY_ID", "")
OFFLINE_POLICY_SIGNING_PRIVATE_KEY = os.environ.get("OFFLINE_POLICY_SIGNING_PRIVATE_KEY", "")
OFFLINE_POLICY_VERIFYING_KEYS_JSON = os.environ.get("OFFLINE_POLICY_VERIFYING_KEYS_JSON", "")
OFFLINE_POLICY_ISSUER = os.environ.get("OFFLINE_POLICY_ISSUER", "hybrid-secure-storage")
OFFLINE_POLICY_AUDIENCE = os.environ.get("OFFLINE_POLICY_AUDIENCE", "hsss-offline-verifier")
OFFLINE_POLICY_MAX_SECONDS = int(os.environ.get("OFFLINE_POLICY_MAX_SECONDS", "86400"))

# Override in production.py; local.py sets True for development.
DEBUG = False

ALLOWED_HOSTS = [
    h.strip()
    for h in os.environ.get("DJANGO_ALLOWED_HOSTS", "").split(",")
    if h.strip()
]

# ---------------------------------------------------------------------------
# Application definition
# ---------------------------------------------------------------------------
DJANGO_APPS = [
    "django.contrib.admin",
    # Keep the custom account app before django.contrib.auth so its
    # security-aware changepassword command takes precedence over Django's.
    "apps.accounts",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

THIRD_PARTY_APPS = [
    "rest_framework",
    "rest_framework_simplejwt",
    "rest_framework_simplejwt.token_blacklist",
    "corsheaders",
]

LOCAL_APPS = [
    "apps.authentication",
    "apps.devices",
    "apps.hardware_auth",
    "apps.permissions",
    "apps.storage",
    "apps.offline_policies",
    "apps.audit",
    "apps.health",
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "common.middleware.RequestIDMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

# ---------------------------------------------------------------------------
# Database — override DATABASE_URL in environment; never hardcode credentials
# ---------------------------------------------------------------------------
_db_url = os.environ.get("DATABASE_URL", "")

if _db_url:
    DATABASES = {
        "default": dj_database_url.parse(
            _db_url,
            conn_max_age=600,
            ssl_require=os.environ.get("DB_SSL_REQUIRE", "true").lower() == "true",
        )
    }
else:
    # Local development fallback: SQLite. Tests against PostgreSQL are required
    # before any production deployment per the release gates in the architecture spec.
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }

# ---------------------------------------------------------------------------
# Caching — shared backend for rate limiting & throttling
# ---------------------------------------------------------------------------
REDIS_URL = os.environ.get("REDIS_URL", "")
if REDIS_URL:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": REDIS_URL,
        }
    }
else:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "secure-backend-cache",
        }
    }

# Proxy IP resolution settings (safe extraction prevents header spoofing)
USE_X_FORWARDED_FOR = os.environ.get("USE_X_FORWARDED_FOR", "false").lower() == "true"
NUM_PROXIES = int(os.environ.get("NUM_PROXIES", "1"))

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---------------------------------------------------------------------------
# Custom user model — must be set before the first migration
# ---------------------------------------------------------------------------
AUTH_USER_MODEL = "accounts.User"

# ---------------------------------------------------------------------------
# Password validation
# ---------------------------------------------------------------------------
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 10}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# ---------------------------------------------------------------------------
# Internationalization
# ---------------------------------------------------------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# ---------------------------------------------------------------------------
# Static files
# ---------------------------------------------------------------------------
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}

# ---------------------------------------------------------------------------
# Django REST Framework
# ---------------------------------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "apps.authentication.authentication.SecureJWTAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        # Deny everything by default; views must explicitly grant access.
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "20/minute",
        "user": "120/minute",
        # Tighter limits defined in common/throttling.py for auth endpoints.
        "auth_login": "5/minute",
        "auth_login_ip": "10/minute",
        "auth_login_user": "5/minute",
        "auth_register": "3/minute",
    },
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 50,
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
    ],
    "EXCEPTION_HANDLER": "common.exceptions.custom_exception_handler",
}

# ---------------------------------------------------------------------------
# Simple JWT
# ---------------------------------------------------------------------------
SIMPLE_JWT = {
    # Short access token lifetime; finalize through testing.
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=10),
    # Refresh token valid for 7 days; rotate on every use.
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "UPDATE_LAST_LOGIN": True,
    "ALGORITHM": "HS256",
    # Uses DJANGO_SECRET_KEY by default; override with JWT_SIGNING_KEY if a
    # separately managed signing key is intentionally configured.
    "SIGNING_KEY": os.environ.get("JWT_SIGNING_KEY", SECRET_KEY),
    "VERIFYING_KEY": None,
    "AUTH_HEADER_TYPES": ("Bearer",),
    "AUTH_HEADER_NAME": "HTTP_AUTHORIZATION",
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
    "TOKEN_TYPE_CLAIM": "token_type",
    # Do NOT put passwords, biometric data, or secrets in JWT claims.
    "TOKEN_OBTAIN_SERIALIZER": "apps.authentication.serializers.CustomTokenObtainPairSerializer",
}

# ---------------------------------------------------------------------------
# CORS — restrict to explicitly configured origins; never wildcard with credentials
# ---------------------------------------------------------------------------
CORS_ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get("CORS_ALLOWED_ORIGINS", "").split(",")
    if o.strip()
]
CORS_ALLOW_CREDENTIALS = True

# ---------------------------------------------------------------------------
# Security headers (enforced in production.py)
# ---------------------------------------------------------------------------
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = "DENY"
SECURE_CONTENT_TYPE_NOSNIFF = True
