from types import SimpleNamespace
from pathlib import Path
import importlib.util
import sys
import unittest
from unittest.mock import patch

from scripts.staging_connectivity_check import (
    TLSVerificationError,
    ensure_project_root_on_path,
    ssl_connect_options,
    validate_neon_endpoint_hosts,
    verify_client_tls,
)


class SSLConnectOptionsTests(unittest.TestCase):
    def test_missing_sslmode_forces_encryption(self):
        options = ssl_connect_options("postgresql://user:pass@host/db")
        self.assertEqual(options, {"sslmode": "require", "connect_timeout": 10})

    def test_preserves_stronger_verify_full_mode(self):
        options = ssl_connect_options("postgresql://user:pass@host/db?sslmode=verify-full")
        self.assertEqual(options, {"connect_timeout": 10})

    def test_does_not_override_explicit_require_mode(self):
        options = ssl_connect_options("postgresql://user:pass@host/db?sslmode=require")
        self.assertEqual(options, {"connect_timeout": 10})

    def test_preserves_verify_ca_mode(self):
        options = ssl_connect_options("postgresql://user:pass@host/db?sslmode=verify-ca")
        self.assertEqual(options, {"connect_timeout": 10})

    def test_refuses_ssl_disabled_or_weaker_modes(self):
        for mode in ("disable", "allow", "prefer", "" ):
            with self.subTest(mode=mode):
                with self.assertRaises(TLSVerificationError):
                    ssl_connect_options(f"postgresql://user:pass@host/db?sslmode={mode}")

    def test_refuses_ambiguous_duplicate_modes(self):
        with self.assertRaises(TLSVerificationError):
            ssl_connect_options("postgresql://user:pass@host/db?sslmode=require&sslmode=verify-full")


class ClientTLSVerificationTests(unittest.TestCase):
    def test_accepts_libpq_report_of_active_tls(self):
        verify_client_tls(SimpleNamespace(info=SimpleNamespace(ssl_in_use=True)))

    def test_fails_when_libpq_reports_no_tls(self):
        with self.assertRaisesRegex(TLSVerificationError, "not active"):
            verify_client_tls(SimpleNamespace(info=SimpleNamespace(ssl_in_use=False)))

    def test_fails_safely_when_driver_has_no_tls_status(self):
        with self.assertRaisesRegex(TLSVerificationError, "cannot be verified"):
            verify_client_tls(SimpleNamespace(info=SimpleNamespace()))

    def test_fails_safely_when_connection_info_is_missing(self):
        with self.assertRaisesRegex(TLSVerificationError, "does not expose"):
            verify_client_tls(SimpleNamespace())

    def test_fails_clearly_when_libpq_rejects_ssl_status_query(self):
        class UnsupportedInfo:
            @property
            def ssl_in_use(self):
                raise RuntimeError("unsupported libpq feature")

        with self.assertRaisesRegex(TLSVerificationError, "could not report"):
            verify_client_tls(SimpleNamespace(info=UnsupportedInfo()))


class DjangoReadinessBootstrapTests(unittest.TestCase):
    def test_project_root_is_added_when_checker_is_run_from_scripts_directory(self):
        project_root = str(Path(__file__).resolve().parents[1])
        scripts_dir = str(Path(project_root) / "scripts")
        with patch.object(sys, "path", [scripts_dir]):
            self.assertIsNone(importlib.util.find_spec("config"))
            resolved_root = ensure_project_root_on_path()
            self.assertEqual(resolved_root, project_root)
            self.assertEqual(sys.path[0], project_root)
            self.assertIsNotNone(importlib.util.find_spec("config"))


class NeonStagingEndpointSafetyTests(unittest.TestCase):
    pooled = "postgresql://u:p@ep-stage-123-pooler.region.aws.neon.tech/db?sslmode=require"
    direct = "postgresql://u:p@ep-stage-123.region.aws.neon.tech/db?sslmode=require"
    expected_pooled = "ep-stage-123-pooler.region.aws.neon.tech"
    expected_direct = "ep-stage-123.region.aws.neon.tech"

    def test_accepts_exact_confirmed_pooled_and_direct_hosts(self):
        validate_neon_endpoint_hosts(
            self.pooled, self.direct, self.expected_pooled, self.expected_direct
        )

    def test_rejects_url_host_not_matching_staging_allowlist(self):
        production_url = self.pooled.replace("ep-stage-123", "ep-prod-999")
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate_neon_endpoint_hosts(
                production_url, self.direct, self.expected_pooled, self.expected_direct
            )

    def test_rejects_direct_host_not_matching_expected_allowlist(self):
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate_neon_endpoint_hosts(
                self.pooled,
                self.direct,
                self.expected_pooled,
                "ep-other-456.region.aws.neon.tech",
            )

    def test_rejects_pooled_host_used_as_direct(self):
        with self.assertRaisesRegex(ValueError, "direct staging endpoint"):
            validate_neon_endpoint_hosts(
                self.pooled,
                self.pooled,
                self.expected_pooled,
                self.expected_pooled,
            )


if __name__ == "__main__":
    unittest.main()
