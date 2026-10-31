#!/usr/bin/env python
"""Run the Django test suite and read-only local API smoke checks."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit


BACKEND_DIR = Path(__file__).resolve().parent
REPORT_DIR = BACKEND_DIR / "test-reports"
HTTP_TIMEOUT_SECONDS = 4


@dataclass(frozen=True)
class SmokeCheck:
    name: str
    path: str
    expected_status: int
    actual_status: int | None
    result: str
    detail: str = ""


@dataclass(frozen=True)
class DjangoTestResult:
    status: str
    exit_code: int
    summary: str


@dataclass(frozen=True)
class SmokeResult:
    status: str
    checks: tuple[SmokeCheck, ...]

    @property
    def passed(self) -> int:
        return sum(check.result == "PASS" for check in self.checks)

    @property
    def failed(self) -> int:
        return sum(check.result == "FAIL" for check in self.checks)


def parse_django_summary(output: str, exit_code: int) -> str:
    """Return a concise test summary without exposing arbitrary test output."""
    ran_match = re.search(r"Ran\s+(\d+)\s+tests?\s+in\s+([\d.]+s)", output)
    outcome_match = re.search(r"^(OK(?: \([^\r\n]*\))?|FAILED(?: \([^\r\n]*\))?)\s*$", output, re.MULTILINE)
    if ran_match:
        outcome = outcome_match.group(1) if outcome_match else ("OK" if exit_code == 0 else "FAILED")
        return f"Ran {ran_match.group(1)} tests in {ran_match.group(2)}; {outcome}."
    if exit_code == 0:
        return "Django test command completed successfully; no standard test summary was emitted."
    return "Django test command failed; see the captured exit status."


def run_django_tests() -> DjangoTestResult:
    command = [sys.executable, "manage.py", "test", "tests", "--verbosity=2"]
    # The test runner must never inherit production credentials or a production
    # database/cache URL. Always use local settings and isolated SQLite tests.
    test_env = os.environ.copy()
    test_env["DJANGO_SETTINGS_MODULE"] = "config.settings.local"
    for name in (
        "DJANGO_SECRET_KEY",
        "JWT_SIGNING_KEY",
        "DATABASE_URL",
        "REDIS_URL",
        "OFFLINE_POLICY_SIGNING_PRIVATE_KEY",
        "OFFLINE_POLICY_VERIFYING_KEYS_JSON",
    ):
        test_env.pop(name, None)
    try:
        completed = subprocess.run(
            command,
            cwd=BACKEND_DIR,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=test_env,
            check=False,
        )
    except OSError as exc:
        # Report only the exception type; subprocess errors can include paths
        # or environment details that do not belong in a user-facing report.
        return DjangoTestResult("FAIL", 1, f"Could not start Django tests ({type(exc).__name__}).")

    summary = parse_django_summary(completed.stdout or "", completed.returncode)
    status = "PASS" if completed.returncode == 0 else "FAIL"
    return DjangoTestResult(status, completed.returncode, summary)


def _valid_base_url(base_url: str) -> tuple[str | None, str | None]:
    try:
        parsed = urlsplit(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return None, "Base URL must be an absolute http:// or https:// URL."
        if not parsed.hostname:
            return None, "Base URL must include a hostname."
        _ = parsed.port  # Force validation of malformed port values.
        if parsed.username is not None or parsed.password is not None:
            return None, "Base URL must not contain embedded credentials."
        if parsed.query or parsed.fragment:
            return None, "Base URL must not contain a query string or fragment."
    except ValueError:
        return None, "Base URL is malformed."
    return base_url.rstrip("/"), None


def run_smoke_tests(base_url: str) -> SmokeResult:
    normalized_url, validation_error = _valid_base_url(base_url)
    checks_to_run = (
        ("Health liveness", "/api/v1/health/live/", 200),
        ("Health readiness", "/api/v1/health/ready/", 200),
        ("Current user without token", "/api/v1/auth/me/", 401),
        ("Current user with invalid bearer token", "/api/v1/auth/me/", 401),
        ("File list without token", "/api/v1/files/", 401),
        (
            "File content without token",
            f"/api/v1/files/{uuid.uuid4()}/content/",
            401,
        ),
    )
    checks: list[SmokeCheck] = []

    if validation_error:
        return SmokeResult(
            "BLOCKED",
            tuple(
                SmokeCheck(name, path, expected, None, "BLOCKED", validation_error)
                for name, path, expected in checks_to_run
            ),
        )

    assert normalized_url is not None
    for name, path, expected_status in checks_to_run:
        headers = {}
        if name == "Current user with invalid bearer token":
            headers["Authorization"] = "Bearer invalid-smoke-test-token"
        request = urllib.request.Request(
            f"{normalized_url}{path}",
            method="GET",
            headers={"Accept": "application/json", **headers},
        )
        try:
            with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
                actual_status = response.status
                detail = ""
        except urllib.error.HTTPError as exc:
            actual_status = exc.code
            exc.close()
            detail = ""
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", None)
            reason_type = type(reason).__name__ if reason is not None else type(exc).__name__
            checks.append(
                SmokeCheck(
                    name,
                    path,
                    expected_status,
                    None,
                    "BLOCKED",
                    f"Could not reach local API ({reason_type}; timeout {HTTP_TIMEOUT_SECONDS}s).",
                )
            )
            continue
        except Exception as exc:
            checks.append(
                SmokeCheck(name, path, expected_status, None, "BLOCKED", f"HTTP request failed ({type(exc).__name__}).")
            )
            continue

        result = "PASS" if actual_status == expected_status else "FAIL"
        checks.append(SmokeCheck(name, path, expected_status, actual_status, result, detail))

    if any(check.result == "BLOCKED" for check in checks):
        stage_status = "BLOCKED"
    elif any(check.result == "FAIL" for check in checks):
        stage_status = "FAIL"
    else:
        stage_status = "PASS"
    return SmokeResult(stage_status, tuple(checks))


def overall_exit_code(django_result: DjangoTestResult, smoke_result: SmokeResult) -> int:
    return 0 if django_result.status == "PASS" and smoke_result.status == "PASS" else 1


def _new_report_path(now: datetime) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = now.strftime("%Y%m%d-%H%M%S")
    candidate = REPORT_DIR / f"backend-test-report-{timestamp}.txt"
    suffix = 1
    while candidate.exists():
        candidate = REPORT_DIR / f"backend-test-report-{timestamp}-{suffix:02d}.txt"
        suffix += 1
    return candidate


def render_report(
    started_at: datetime,
    finished_at: datetime,
    django_result: DjangoTestResult,
    smoke_result: SmokeResult,
    base_url: str,
) -> str:
    overall = "PASS" if overall_exit_code(django_result, smoke_result) == 0 else "FAIL"
    normalized_url, url_error = _valid_base_url(base_url)
    safe_base_url = normalized_url if not url_error else "[invalid base URL omitted]"
    rows = [
        "Hybrid Secure Storage System - Backend Test Report",
        f"Started: {started_at.isoformat(timespec='seconds')}",
        f"Finished: {finished_at.isoformat(timespec='seconds')}",
        f"API base URL: {safe_base_url}",
        "",
        f"Django test stage: {django_result.status} (exit code {django_result.exit_code})",
        f"Summary: {django_result.summary}",
        "Command: python manage.py test tests --verbosity=2",
        "",
        f"API smoke stage: {smoke_result.status}",
        "Smoke checks:",
    ]
    for check in smoke_result.checks:
        actual = str(check.actual_status) if check.actual_status is not None else "unavailable"
        suffix = f" - {check.detail}" if check.detail else ""
        rows.append(
            f"- {check.name}: expected HTTP {check.expected_status}, actual HTTP {actual}: {check.result}{suffix}"
        )
    rows.extend(
        [
            f"Smoke total: {smoke_result.passed} passed, {smoke_result.failed} failed, "
            f"{len(smoke_result.checks) - smoke_result.passed - smoke_result.failed} blocked.",
            "",
            f"Overall result: {overall}",
        ]
    )
    return "\n".join(rows) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        default=os.environ.get("BACKEND_BASE_URL", "http://127.0.0.1:8000"),
        help="Local Django API base URL (default: http://127.0.0.1:8000).",
    )
    args = parser.parse_args(argv)

    started_at = datetime.now().astimezone()
    print("Running Django test suite...", flush=True)
    django_result = run_django_tests()
    print(
        f"Django tests: {django_result.status} (exit code {django_result.exit_code}) - {django_result.summary}",
        flush=True,
    )

    print("Running read-only local API smoke checks...", flush=True)
    smoke_result = run_smoke_tests(args.base_url)
    finished_at = datetime.now().astimezone()
    report = render_report(started_at, finished_at, django_result, smoke_result, args.base_url)
    report_path = _new_report_path(finished_at)
    report_path.write_text(report, encoding="utf-8")

    print("\n" + report, end="")
    print(f"Report saved: {report_path}")
    return overall_exit_code(django_result, smoke_result)


if __name__ == "__main__":
    raise SystemExit(main())
