"""
Local development settings.
Set DJANGO_SETTINGS_MODULE=config.settings.local in your .env file.
Never use these settings in production.
"""

import os
import secrets

# Generate a throwaway local-only key instead of keeping a known key in source.
os.environ.setdefault("DJANGO_SECRET_KEY", secrets.token_urlsafe(64))
os.environ.setdefault("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1")
os.environ.setdefault("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")
os.environ.setdefault("DB_SSL_REQUIRE", "false")

from .base import *  # noqa: F401,F403,E402

DEBUG = True

ALLOWED_HOSTS = ["localhost", "127.0.0.1", "0.0.0.0", "testserver"]

# Show SQL queries in local development
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "[{levelname}] {asctime} {module} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "DEBUG",
    },
    "loggers": {
        "django.db.backends": {
            "handlers": ["console"],
            "level": "INFO",  # Set to DEBUG to see all SQL queries
            "propagate": False,
        },
        "secure_backend": {
            "handlers": ["console"],
            "level": "DEBUG",
            "propagate": False,
        },
    },
}

# Relax JWT lifetime for local development
from datetime import timedelta
SIMPLE_JWT = {
    **SIMPLE_JWT,
    "ACCESS_TOKEN_LIFETIME": timedelta(hours=1),
}
