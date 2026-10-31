"""Non-destructive connectivity checks for explicitly configured staging services.

This script performs PostgreSQL SELECTs only and a uniquely named Redis
set/get/delete round trip. It never runs migrations or destructive SQL.
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


class TLSVerificationError(Exception):
    """Raised when libpq cannot prove that client-side TLS is active."""


def ensure_project_root_on_path() -> str:
    """Make root Django packages importable when this nested script is run directly."""
    project_root = str(Path(__file__).resolve().parents[1])
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    return project_root


def validate_neon_endpoint_hosts(
    pooled_url: str,
    direct_url: str,
    expected_pooled_host: str,
    expected_direct_host: str,
) -> None:
    """Require both URLs to match operator-confirmed staging endpoint hosts."""
    pooled_host = (urlsplit(pooled_url).hostname or "").lower().rstrip(".")
    direct_host = (urlsplit(direct_url).hostname or "").lower().rstrip(".")
    expected_pooled_host = expected_pooled_host.strip().lower().rstrip(".")
    expected_direct_host = expected_direct_host.strip().lower().rstrip(".")

    if not expected_pooled_host or not expected_direct_host:
        raise ValueError("Expected Neon staging endpoint hostnames are required.")
    if pooled_host != expected_pooled_host:
        raise ValueError("DATABASE_URL host does not match the confirmed staging pooled endpoint.")
    if direct_host != expected_direct_host:
        raise ValueError("NEON_DIRECT_DATABASE_URL host does not match the confirmed staging direct endpoint.")
    if "-pooler." not in pooled_host:
        raise ValueError("Expected pooled staging endpoint hostname must contain -pooler.")
    if "-pooler." in direct_host:
        raise ValueError("Expected direct staging endpoint hostname must not contain -pooler.")
    if pooled_host.replace("-pooler.", ".", 1) != direct_host:
        raise ValueError("Expected pooled and direct staging endpoints must be matching counterparts.")


def ssl_connect_options(url: str) -> dict[str, object]:
    """Require encryption without overriding a stronger URL verification mode."""
    modes = parse_qs(urlsplit(url).query, keep_blank_values=True).get("sslmode", [])
    if len(modes) > 1:
        raise TLSVerificationError("URL must contain at most one sslmode parameter.")
    if not modes:
        # Enforce encryption if the provider URL omits the parameter. Do not
        # use this as proof; verify the negotiated client connection afterwards.
        return {"sslmode": "require", "connect_timeout": 10}
    if modes[0] not in {"require", "verify-ca", "verify-full"}:
        raise TLSVerificationError(
            "URL sslmode must be require, verify-ca, or verify-full; weaker modes are refused."
        )
    # Leave an explicit secure mode in the URL intact (especially verify-full).
    return {"connect_timeout": 10}


def verify_client_tls(conn) -> None:
    """Use libpq's live connection status, not a server-side SQL view.

    This proves negotiated encryption to the endpoint. Certificate/hostname
    verification remains governed by the preserved sslmode (verify-full is
    stronger than require).
    """
    info = getattr(conn, "info", None)
    if info is None:
        raise TLSVerificationError(
            "psycopg2/libpq does not expose connection.info.ssl_in_use; client TLS cannot be verified."
        )
    try:
        active = info.ssl_in_use
    except AttributeError as exc:
        raise TLSVerificationError(
            "psycopg2/libpq does not expose connection.info.ssl_in_use; client TLS cannot be verified."
        ) from exc
    except Exception as exc:
        raise TLSVerificationError(
            "libpq could not report client TLS status; client TLS cannot be verified."
        ) from exc
    if active is not True:
        raise TLSVerificationError(
            "libpq reports that client-to-endpoint TLS is not active; refusing to claim SSL verification."
        )


def fail(message: str) -> None:
    print(f"FAIL: {message}")
    raise SystemExit(1)


def required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value or "REPLACE_WITH" in value or "YOUR_ENDPOINT" in value:
        fail(f"Set {name} to the staging value before running this check.")
    return value


def check_postgres(label: str, url: str, expected_name: str) -> None:
    try:
        connect_options = ssl_connect_options(url)
    except TLSVerificationError as exc:
        fail(f"PostgreSQL {label} TLS configuration rejected: {exc}")
    try:
        import psycopg2

        parsed = urlsplit(url)
        if parsed.scheme not in {"postgres", "postgresql", "postgresql+psycopg2"}:
            fail(f"{label} URL must use a PostgreSQL scheme.")
        if not parsed.hostname or not parsed.path.strip("/"):
            fail(f"{label} URL must include a host and database name.")
        with psycopg2.connect(url, **connect_options) as conn:
            verify_client_tls(conn)
            with conn.cursor() as cursor:
                cursor.execute("SELECT current_database()")
                row = cursor.fetchone()
        if not row:
            fail(f"{label} PostgreSQL connection did not report its database identity.")
        (actual_name,) = row
        if actual_name != expected_name:
            fail(f"{label} connected to database {actual_name!r}, expected {expected_name!r}; stopping.")
        print(f"PASS: PostgreSQL {label}: expected staging database confirmed; SSL active.")
    except TLSVerificationError as exc:
        fail(f"PostgreSQL {label} TLS verification unavailable: {exc}")
    except SystemExit:
        raise
    except Exception:
        # Driver exception strings may contain connection details; never print them.
        fail(f"PostgreSQL {label} connection/query failed (details suppressed).")


def main() -> int:
    expected_name = required("STAGING_EXPECTED_DB_NAME")
    pooled_url = required("DATABASE_URL")
    direct_url = required("NEON_DIRECT_DATABASE_URL")
    expected_pooled_host = required("STAGING_EXPECTED_NEON_POOLED_HOST")
    expected_direct_host = required("STAGING_EXPECTED_NEON_DIRECT_HOST")
    redis_url = required("REDIS_URL")

    try:
        validate_neon_endpoint_hosts(
            pooled_url,
            direct_url,
            expected_pooled_host,
            expected_direct_host,
        )
    except ValueError as exc:
        fail(f"Neon staging endpoint safety check failed: {exc}")
    if urlsplit(redis_url).scheme != "rediss":
        fail("REDIS_URL must use rediss:// to require TLS.")

    check_postgres("pooled", pooled_url, expected_name)
    check_postgres("direct (read-only check)", direct_url, expected_name)

    try:
        import redis

        client = redis.Redis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=10,
            socket_timeout=10,
        )
        if client.ping() is not True:
            fail("Upstash Redis PING returned an unexpected response.")
        print("PASS: Upstash Redis TLS URL and PING.")
    except SystemExit:
        raise
    except Exception:
        fail("Upstash Redis TLS connection or PING failed (details suppressed).")

    key = f"hss:staging-connectivity:{uuid.uuid4()}"
    value = str(uuid.uuid4())
    try:
        if client.set(key, value, ex=30) is not True:
            fail("Redis test-key SET failed.")
        if client.get(key) != value:
            fail("Redis test-key GET did not return the written value.")
        if client.delete(key) != 1:
            fail("Redis test-key DELETE did not remove exactly the test key.")
        print("PASS: Redis set/get/delete round trip.")
    except SystemExit:
        try:
            client.delete(key)
        except Exception:
            pass
        raise
    except Exception:
        try:
            client.delete(key)
        except Exception:
            pass
        fail("Redis cache round trip failed (details suppressed).")

    # Django readiness uses DATABASE_URL (pooled) and REDIS_URL. The production
    # settings checks enforce PostgreSQL, TLS, secret separation, and RedisCache.
    try:
        ensure_project_root_on_path()
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.production")
        os.environ.setdefault("DB_SSL_REQUIRE", "true")
        os.environ.setdefault("DJANGO_SECRET_KEY", "staging-check-placeholder-" + "d" * 50)
        os.environ.setdefault("JWT_SIGNING_KEY", "staging-check-jwt-placeholder-" + "j" * 50)
        os.environ.setdefault("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1")
        import django

        django.setup()
        from django.conf import settings
        from django.test import Client

        db = settings.DATABASES["default"]
        if db["ENGINE"] != "django.db.backends.postgresql":
            fail("Django runtime database is not PostgreSQL; stopping.")
        if db.get("DISABLE_SERVER_SIDE_CURSORS") is not True:
            fail("Django pooled connection must disable server-side cursors.")
        response = Client(HTTP_HOST="localhost").get("/api/v1/health/ready/", secure=True)
        if response.status_code != 200:
            fail(f"Django readiness returned HTTP {response.status_code}; dependencies may be unavailable.")
        print("PASS: Django production settings and local HTTPS readiness endpoint.")
    except SystemExit:
        raise
    except Exception as exc:
        # Include only the exception class to make failures diagnosable without
        # risking URL, username, password, or provider detail disclosure.
        fail(f"Django readiness/configuration check failed ({type(exc).__name__}; details suppressed).")

    print("All staging connectivity checks passed. No migrations were run.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
