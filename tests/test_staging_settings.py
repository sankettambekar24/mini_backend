import os
import subprocess
import sys
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]


class StagingSettingsGuardTests(unittest.TestCase):
    def load_staging_settings(self, **overrides):
        env = os.environ.copy()
        env.update(
            {
                "DJANGO_SETTINGS_MODULE": "config.settings.staging",
                "DJANGO_SECRET_KEY": "staging-test-secret-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                "JWT_SIGNING_KEY": "staging-test-jwt-secret-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                "DJANGO_ALLOWED_HOSTS": "localhost,127.0.0.1",
                "DATABASE_URL": "postgresql://stage_user:stage_pw@ep-stage-123.region.aws.neon.tech/hss_stage?sslmode=require",
                "NEON_DIRECT_DATABASE_URL": "postgresql://stage_user:stage_pw@ep-stage-123.region.aws.neon.tech/hss_stage?sslmode=require",
                "REDIS_URL": "rediss://default:placeholder@cache.example:6379",
                "DB_SSL_REQUIRE": "true",
                "STAGING_EXPECTED_NEON_DIRECT_HOST": "ep-stage-123.region.aws.neon.tech",
                "STAGING_EXPECTED_DB_NAME": "hss_stage",
            }
        )
        env.update(overrides)
        return subprocess.run(
            [sys.executable, "-c", "import config.settings.staging"],
            cwd=BACKEND_DIR,
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )

    def test_accepts_expected_direct_staging_target_without_connecting(self):
        result = self.load_staging_settings()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_pooled_url_for_staging_migration_settings(self):
        result = self.load_staging_settings(
            DATABASE_URL="postgresql://stage_user:stage_pw@ep-stage-123-pooler.region.aws.neon.tech/hss_stage"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("direct endpoint", result.stderr)

    def test_rejects_production_or_other_endpoint(self):
        result = self.load_staging_settings(
            DATABASE_URL="postgresql://stage_user:stage_pw@ep-prod-987.region.aws.neon.tech/hss_stage"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("confirmed staging direct endpoint", result.stderr)

    def test_rejects_wrong_database_name(self):
        result = self.load_staging_settings(
            DATABASE_URL="postgresql://stage_user:stage_pw@ep-stage-123.region.aws.neon.tech/production"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected staging database", result.stderr)

    def test_requires_expected_staging_identity(self):
        result = self.load_staging_settings(STAGING_EXPECTED_NEON_DIRECT_HOST="")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("require STAGING_EXPECTED_NEON_DIRECT_HOST", result.stderr)


if __name__ == "__main__":
    unittest.main()
