"""Isolated settings for build-time static asset collection only.

This module deliberately discards deployment credentials from the build
process and creates a throwaway signing key in memory. It must never be used
to serve requests.
"""

import os
import secrets

for _name in (
    "DJANGO_SECRET_KEY",
    "JWT_SIGNING_KEY",
    "DATABASE_URL",
    "REDIS_URL",
    "OFFLINE_POLICY_SIGNING_PRIVATE_KEY",
    "OFFLINE_POLICY_VERIFYING_KEYS_JSON",
):
    os.environ.pop(_name, None)
os.environ["DJANGO_SECRET_KEY"] = secrets.token_urlsafe(64)

from .base import *  # noqa: F401,F403,E402

DEBUG = False
ALLOWED_HOSTS = ["localhost"]
CORS_ALLOWED_ORIGINS = []
CSRF_TRUSTED_ORIGINS = []
CORS_ALLOW_CREDENTIALS = False
