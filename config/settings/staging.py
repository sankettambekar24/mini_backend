"""Fail-closed settings guard for staging-only migration/test operations.

Select this module only in an operator process whose DATABASE_URL is the
Neon direct URL for the confirmed staging branch. Runtime connectivity checks
continue to use config.settings.production with the pooled URL.
"""

import os
from urllib.parse import unquote, urlsplit

from django.core.exceptions import ImproperlyConfigured

from .production import *  # noqa: F401,F403

_expected_host = os.environ.get("STAGING_EXPECTED_NEON_DIRECT_HOST", "").strip().lower().rstrip(".")
_expected_db = os.environ.get("STAGING_EXPECTED_DB_NAME", "").strip()
_database_url = os.environ.get("DATABASE_URL", "").strip()
_parsed = urlsplit(_database_url)
_actual_host = (_parsed.hostname or "").lower().rstrip(".")
_actual_db = unquote(_parsed.path.lstrip("/"))

if not _expected_host or not _expected_db:
    raise ImproperlyConfigured(
        "Staging commands require STAGING_EXPECTED_NEON_DIRECT_HOST and STAGING_EXPECTED_DB_NAME."
    )
if "-pooler." in _actual_host:
    raise ImproperlyConfigured("Staging migration/test settings require the Neon direct endpoint, not pooled URL.")
if _actual_host != _expected_host:
    raise ImproperlyConfigured("DATABASE_URL does not match the confirmed staging direct endpoint.")
if _actual_db != _expected_db:
    raise ImproperlyConfigured("DATABASE_URL database name does not match the expected staging database.")
