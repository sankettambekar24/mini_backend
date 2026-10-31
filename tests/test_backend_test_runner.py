import unittest

from run_backend_tests import (
    DjangoTestResult,
    SmokeCheck,
    SmokeResult,
    overall_exit_code,
    parse_django_summary,
    render_report,
)
from datetime import datetime, timezone


class BackendTestRunnerTests(unittest.TestCase):
    def test_parse_django_summary_includes_test_count_and_skips(self):
        output = "Ran 8 tests in 1.25s\n\nOK (skipped=2)\n"
        self.assertEqual(
            parse_django_summary(output, 0),
            "Ran 8 tests in 1.25s; OK (skipped=2).",
        )

    def test_nonzero_exit_code_fails_overall_even_if_smoke_passes(self):
        django = DjangoTestResult("FAIL", 1, "Ran 1 test; FAILED.")
        smoke = SmokeResult("PASS", (SmokeCheck("live", "/live/", 200, 200, "PASS"),))
        self.assertEqual(overall_exit_code(django, smoke), 1)

    def test_blocked_smoke_stage_fails_overall(self):
        django = DjangoTestResult("PASS", 0, "Ran 1 test; OK.")
        smoke = SmokeResult(
            "BLOCKED",
            (SmokeCheck("live", "/live/", 200, None, "BLOCKED", "connection unavailable"),),
        )
        self.assertEqual(overall_exit_code(django, smoke), 1)

    def test_report_separates_stages_and_lists_smoke_results(self):
        now = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        django = DjangoTestResult("PASS", 0, "Ran 2 tests in 0.1s; OK.")
        smoke = SmokeResult("FAIL", (SmokeCheck("live", "/live/", 200, 503, "FAIL"),))
        report = render_report(now, now, django, smoke, "http://127.0.0.1:8000")
        self.assertIn("Django test stage: PASS", report)
        self.assertIn("API smoke stage: FAIL", report)
        self.assertIn("expected HTTP 200, actual HTTP 503: FAIL", report)
        self.assertIn("Overall result: FAIL", report)


if __name__ == "__main__":
    unittest.main()
