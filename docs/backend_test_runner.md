# Backend test runner

## Prerequisites

- Python and the backend dependencies from `requirements.txt` must be available in the active environment.
- The Django suite uses Django's isolated test database. Use local/test database settings; do not point `DATABASE_URL` at production.
- For the live API checks, run the local Django server separately and ensure it is available at `http://127.0.0.1:8000` (or provide another local base URL). The runner never starts or stops a server.

## Run

From `backend/`, run:

```powershell
python run_backend_tests.py
```

The default can be overridden with `BACKEND_BASE_URL` or with `--base-url`. The command-line value takes precedence. To target another local server:

```powershell
python run_backend_tests.py --base-url http://127.0.0.1:8010
```

The runner first executes `python manage.py test tests --verbosity=2` under explicit local settings with `DATABASE_URL` and `REDIS_URL` removed from the test subprocess, then makes six read-only GET requests. This prevents the runner from using a production database even if the caller's shell has production environment variables. It does not create users or file metadata, submit credentials, or change application state. The invalid bearer value is a fixed dummy string and is never printed.

## Reports and results

Each run saves a plain-text summary under `test-reports/backend-test-report-YYYYMMDD-HHMMSS.txt`. The directory's generated `.txt` reports are git-ignored. The report includes test exit status and summary, each smoke check's expected and actual HTTP status, stage results, and the overall result. The full test process output is captured in memory to extract the summary; raw test logs are not copied to the report.

The process exits `0` only when both stages pass. Django test failures, unexpected HTTP statuses, an invalid base URL, or an unreachable server produce a non-zero exit. An unreachable server marks the smoke stage `BLOCKED`; it does not imply the HTTP checks passed. A failed Django stage does not prevent the read-only smoke stage from running.

The HTTP checks cover liveness and readiness (200), unauthenticated and invalid-token current-user requests (401), unauthenticated file listing (401), and unauthenticated content access for a random UUID (401). The random UUID is used only to check the authentication boundary; it is not expected to return 503.
