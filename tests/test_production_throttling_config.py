import os
import subprocess
import sys
from pathlib import Path

from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase
from common.throttle_config import validate_production_throttle_cache


BACKEND_DIR = Path(__file__).resolve().parents[1]


class ProductionThrottleConfigurationTests(SimpleTestCase):
    def load_production_settings(self, redis_url, **overrides):
        env = os.environ.copy()
        env.update(
            {
                "DJANGO_SETTINGS_MODULE": "config.settings.production",
                "DJANGO_SECRET_KEY": "test-only-secret-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                "JWT_SIGNING_KEY": "separate-test-jwt-key-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                "DJANGO_ALLOWED_HOSTS": "testserver",
                "DATABASE_URL": "postgresql://test:test@127.0.0.1:5432/test_db",
                "REDIS_URL": redis_url,
                "DB_SSL_REQUIRE": "true",
                "CORS_ALLOWED_ORIGINS": "https://client.example.test",
                "CSRF_TRUSTED_ORIGINS": "https://api.example.test",
            }
        )
        env.update(overrides)
        return subprocess.run(
            [sys.executable, "-c", "import config.settings.production"],
            cwd=BACKEND_DIR,
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )

    def test_production_rejects_missing_shared_redis_configuration(self):
        result = self.load_production_settings("")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("REDIS_URL is required", result.stderr)

    def test_production_rejects_malformed_or_non_redis_url(self):
        for value in ("not-a-url", "http://cache.example:6379", "redis://"):
            with self.subTest(value=value):
                result = self.load_production_settings(value)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("valid redis:// or rediss:// URL", result.stderr)

    def test_production_accepts_shared_redis_url_and_uses_redis_cache(self):
        result = self.load_production_settings("rediss://cache.example:6380/2")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_production_rejects_missing_database_url(self):
        result = self.load_production_settings("redis://cache.example:6379/0", DATABASE_URL="")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DATABASE_URL is required", result.stderr)

    def test_production_rejects_sqlite_database_url(self):
        result = self.load_production_settings("redis://cache.example:6379/0", DATABASE_URL="sqlite:///prod.sqlite3")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Production requires PostgreSQL", result.stderr)

    def test_production_rejects_database_tls_opt_out(self):
        result = self.load_production_settings("redis://cache.example:6379/0", DB_SSL_REQUIRE="false")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DB_SSL_REQUIRE must remain true", result.stderr)

    def test_production_requires_separate_jwt_signing_key(self):
        result = self.load_production_settings("redis://cache.example:6379/0", JWT_SIGNING_KEY="")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("JWT_SIGNING_KEY must be a separate environment secret", result.stderr)

    def test_production_rejects_http_cors_and_csrf_origins(self):
        for variable in ("CORS_ALLOWED_ORIGINS", "CSRF_TRUSTED_ORIGINS"):
            with self.subTest(variable=variable):
                result = self.load_production_settings(
                    "redis://cache.example:6379/0", **{variable: "http://web.example.org"}
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("must use HTTPS", result.stderr)

    def test_build_settings_discard_deployment_secrets(self):
        env = os.environ.copy()
        env.update(
            {
                "DJANGO_SETTINGS_MODULE": "config.settings.build",
                "DJANGO_SECRET_KEY": "production-secret-sentinel",
                "JWT_SIGNING_KEY": "jwt-secret-sentinel",
                "DATABASE_URL": "postgresql://secret:secret@example.invalid/prod",
                "REDIS_URL": "redis://secret@example.invalid/0",
            }
        )
        code = (
            "from django.conf import settings; "
            "assert settings.DATABASES['default']['ENGINE'] == 'django.db.backends.sqlite3'; "
            "assert settings.CACHES['default']['BACKEND'].endswith('LocMemCache'); "
            "assert settings.SECRET_KEY != 'production-secret-sentinel'; "
            "assert settings.SIMPLE_JWT['SIGNING_KEY'] != 'jwt-secret-sentinel'; "
            "assert settings.DEBUG is False"
        )
        result = subprocess.run(
            [sys.executable, "-c", code], cwd=BACKEND_DIR, env=env,
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_production_rejects_process_local_cache_even_with_redis_url(self):
        with self.assertRaisesMessage(ImproperlyConfigured, "requires Django RedisCache"):
            validate_production_throttle_cache(
                "redis://cache.example:6379/0",
                {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
            )

    def test_local_settings_remain_usable_without_redis(self):
        env = os.environ.copy()
        env["DJANGO_SETTINGS_MODULE"] = "config.settings.local"
        env.pop("REDIS_URL", None)
        code = (
            "from django.conf import settings; "
            "assert 'LocMemCache' in settings.CACHES['default']['BACKEND']"
        )
        result = subprocess.run(
            [sys.executable, "-c", code], cwd=BACKEND_DIR, env=env,
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_local_throttle_cache_stores_and_increments_counters(self):
        key = "test-auth-throttle-counter"
        cache.delete(key)
        self.assertTrue(cache.add(key, 1, timeout=60))
        self.assertEqual(cache.incr(key), 2)
        self.assertEqual(cache.get(key), 2)
        cache.delete(key)
