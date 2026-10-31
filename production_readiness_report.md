# HSS Django Backend — Production Readiness Audit

**Updated:** 2026-10-31 (hosting configuration addendum supersedes older Render/Render Postgres instructions below)  
**Project:** `C:\mini project\backend`  
**Decision:** **NO-GO for Render deployment yet.** Real PostgreSQL and Redis integration now pass locally, but Render-specific plan, hostname/proxy, HTTPS-edge behavior, and release/backup checks remain unverified.

## Executive findings

The code and Render configuration now fail closed for missing/non-PostgreSQL database URLs, missing Redis, weak/missing production signing keys, non-HTTPS browser origins, or PostgreSQL TLS opt-out. Local settings selection is explicit; build-time static collection uses isolated settings that discard production credentials. Render now has Python 3.14.6 pinned, an explicit Free plan, no automatic migration command, and a DB+Redis readiness health path. Static collection and the production Django deploy check pass.

Disposable PostgreSQL 16.15 and Redis 7 services were reachable at the user-provided test ports. Django connected to `hss_test_db` using PostgreSQL and RedisCache. All migrations were applied to `hss_test_db`; the full 151-test suite ran against PostgreSQL's separate `test_hss_test_db` and Redis. The existing development SQLite file was not used or modified. Render has not been deployed and its selected plan, service hostname, proxy header chain, and HTTPS edge remain unverified.

## Latest PostgreSQL and Redis integration verification

- Connected with the active project virtual environment (`.venv`) and `DJANGO_SETTINGS_MODULE=config.settings.local`, setting `DATABASE_URL` only to the disposable `hss_test_db` service and `REDIS_URL` only to the disposable Redis service. Django printed the sanitized engine/name before testing: `django.db.backends.postgresql`, `hss_test_db`; server reported PostgreSQL 16.15.
- Cache settings resolved to `django.core.cache.backends.redis.RedisCache`. Real Redis set/get/delete operations passed. The login throttle integration test passed against Redis and produced the expected HTTP 429 after the configured limit.
- Ran `python manage.py migrate --noinput` against `hss_test_db`: **44 migration records applied**, then confirmed `current_database()` returned `hss_test_db`. Django's test runner used the separate PostgreSQL database `test_hss_test_db`.
- Full suite: `python manage.py test tests --verbosity=1 --keepdb` using PostgreSQL and Redis: **151 tests passed, 0 skipped**. PostgreSQL concurrency tests for admin bootstrap and replay passed. Audit append-only transaction/constraint tests also passed against PostgreSQL. The first PostgreSQL attempt exposed nullable-join `FOR UPDATE` failure in hardware auth; row locks now target only `AuthAttempt` (`of=("self",)`). Concurrency workers now close their own connections so test DB teardown does not retain thread sessions.
- HTTP smoke tests against a live local Django server configured to PostgreSQL and Redis: **6/6 passed** (liveness/readiness 200, unauthenticated protected routes 401).
- Readiness was tested through Django's HTTP test client with real dependencies configured to unavailable ports: PostgreSQL unavailable produced **503** with `database=unavailable, cache=ok`; Redis unavailable produced **503** with `database=ok, cache=unavailable`.
- `python manage.py makemigrations --check --dry-run` with PostgreSQL selected: **No changes detected.**
- No test reported skips. The two PostgreSQL row-lock tests that were skipped on SQLite executed on PostgreSQL. The previous standalone SQLite baseline of 151 passed / 2 skipped remains historical and is superseded for database verification by this PostgreSQL run.
- Test database `test_hss_test_db` was retained by `--keepdb` for reproducibility. The explicit migration target was `hss_test_db`; Django's test runner applied migrations to its separate test DB as part of the normal test setup.
- `db.sqlite3` remained 282,624 bytes with its prior observed timestamp (2026-10-29 18:59); no SQLite database migration command was run. No MySQL or ExpenseTracker containers were accessed.
- Redis 8.1 client emits a debug note because Redis 7 does not support `CLIENT MAINT_NOTIFICATIONS`; Redis operations and throttling still passed. Monitor this compatibility log or align client/server versions if it is noisy in deployment.
- Timestamped current test report: [`test-reports/backend-postgres-redis-integration-20261031-012720.txt`](test-reports/backend-postgres-redis-integration-20261031-012720.txt).

## Final Render-specific readiness audit (no resources created)

### Plan and service limitations

- Historical audit snapshot (superseded by the current Free + Neon + Upstash plan at the end of this report): at that time plan was unset and a paid pre-deploy migration was configured. Current `render.yaml` explicitly selects Free and removes automatic migrations.
- Historical Render-provider limitations note: current Render docs do support custom domains and managed TLS on Free; Free still sleeps when idle, uses ephemeral filesystem, and lacks jobs/shell/pre-deploy. Render Postgres/Key Value limits are no longer applicable to the selected Neon/Upstash services. See the current hosting plan for provider-specific constraints.
- A paid Postgres database has recovery features; PITR and export retention vary by workspace plan. Confirm the actual database plan and recovery window in the Dashboard before relying on them. [Render backup and restore guide](https://render.com/articles/how-to-backup-and-restore-postgresql-databases)

### Hostname, proxy, HTTPS, CSRF, and health

- Configuration review: `RENDER_EXTERNAL_HOSTNAME` is appended to `ALLOWED_HOSTS`; `DJANGO_ALLOWED_HOSTS` accepts exact additional hostnames and wildcard is rejected. `SECURE_PROXY_SSL_HEADER` is `HTTP_X_FORWARDED_PROTO=https`; HTTPS redirect, secure session/CSRF cookies, and HSTS are enabled. `CORS_ALLOW_CREDENTIALS=False`; CORS is empty unless exact HTTPS origins are configured. `CSRF_TRUSTED_ORIGINS` accepts HTTPS origins only. Production `manage.py check --deploy` with throwaway values passed, and settings assertions confirmed these values. This is configuration verification only; no Render hostname or request was available.
- Render terminates TLS at its edge and forwards plain HTTP to the app; Render documents `X-Forwarded-Proto` for recovering the original scheme. The current Django proxy setting matches that model. [Render web service TLS and headers](https://render.com/tutorials/web-service-vs-static-site/web-services)
- **Client-IP trust remains a blocker:** production currently sets `USE_X_FORWARDED_FOR=True`, `NUM_PROXIES=1`; `get_client_ip()` selects the rightmost `X-Forwarded-For` value. Render says public traffic traverses Cloudflare and its load balancers and directs applications to use XFF; Cloudflare documents that XFF may contain a proxy chain and recommends `CF-Connecting-IP` for a consistent single client address. The actual Render-to-app header chain and spoofed-header behavior have not been observed. Validate the chosen approach against the live Render service and test a client-supplied forged XFF before enabling login throttling for production users. Do not assume the current `NUM_PROXIES=1` extraction is correct. [Render client-IP guidance](https://render.com/articles/how-render-handles-ddos-attacks), [Cloudflare header behavior](https://developers.cloudflare.com/fundamentals/reference/http-headers/)
- Health configuration points Render at `/api/v1/health/ready/`. On local PostgreSQL/Redis, readiness and all 6 HTTP smoke checks passed; against unavailable dependency ports readiness returned 503 as intended. The readiness endpoint checks DB and Redis on each probe and health routes bypass DRF throttling. This has not been checked through Render's health-check agent or live edge. Keep the liveness route separate; it does not check dependencies.
- `manage.py check --deploy` passed under production settings with throwaway audit values, and production settings assertions passed. The provided PostgreSQL test server does not support TLS, so it could not exercise the production-required `DB_SSL_REQUIRE=true` database connection or healthy readiness under `config.settings.production`.
- Add only the actual Render `onrender.com` hostname (platform-provided) and any chosen custom domain to the host configuration. Desktop bearer-token API requests do not require CORS or CSRF origin exceptions; keep both origin lists empty unless a browser-based client/admin flow actually needs an exact HTTPS origin.

### Database connections and pooling

- `DATABASE_URL` resolves with `CONN_MAX_AGE=600`; no Django/Psycopg or Render PgBouncer pool is configured. Gunicorn currently runs two synchronous workers. Initial direct connection demand is approximately one DB connection per active worker (two per instance), with temporary rollout overlap potentially doubling that, plus a pre-deploy migration connection and administrative headroom. Validate this budget against the actual Render Postgres plan and `max_connections`; current-generation limits are memory-tiered (100 below 8 GB, 200 below 16 GB, 400 below 32 GB, 500 at/above 32 GB; legacy plans differ). [Render Postgres connection limits](https://render.com/docs/postgresql-creating-connecting)
- Use the same-region internal database URL on the default direct port. Pooling is not required for the current two-worker baseline; measure first. If enabled later, update `DATABASE_URL` to Render's pooled URL (port 6432) and test against transaction-level PgBouncer behavior. Render pooling requires paid Postgres and restarts the database when enabled. [Render Postgres connection pooling](https://render.com/docs/postgresql-connection-pooling)

### Migration ordering and recovery

- The isolated PostgreSQL migration plan showed all 44 migration records applied. The dependency-ordered chain passed on PostgreSQL 16.15. Current migrations declare no `atomic = False`; the two custom `RunPython` migrations provide reverse handlers, and the audit-trigger migration explicitly removes its trigger/function on reverse. `makemigrations --check --dry-run` is clean.
- A failed pre-deploy command cancels that deploy and leaves the last successful version serving. Earlier migrations that already committed remain applied; Django's default PostgreSQL migration atomicity rolls back the failing migration, not earlier ones. [Render deploy failure behavior](https://render.com/docs/deploys)
- For this first controlled release, use a new, empty production database and keep the old service/code path untouched until readiness is confirmed. Review `python manage.py migrate --plan` against the intended production DB before applying. For future releases, use expand/contract changes compatible with both old and new code during rollout. Prefer a forward corrective migration after writes have occurred; only reverse a migration after verifying it is reversible and data-safe. For recovery, restore to a **new** database and validate it before switching `DATABASE_URL`; do not run `--clean`, drop a production schema, or point a restore at a database containing needed data.

### Backup and restore rehearsal procedure

No Render database exists, so no production backup or restore was attempted. Before production data is written, select a paid Postgres plan with recovery features and rehearse a logical backup/restore using a separate blank database:

1. From the Render Dashboard, create and download an on-demand export (or use `pg_dump` from a trusted workstation). Keep it encrypted outside the repository and service filesystem. Paid Render exports are retained for a limited time; copy the backup to durable protected storage. Never place credentials or dumps in Git or test reports.
2. For a portable custom-format dump from PowerShell, set `PGHOST`, `PGPORT`, `PGUSER`, and `PGDATABASE` to the intended database, set `PGSSLMODE=require`, then run `pg_dump.exe --password --format=custom --file <protected-backup-path>`. `--password` prompts interactively; do not put a password in the command, URI, script, or `PGPASSWORD`. Use a PostgreSQL client version at least as new as the server major version.
3. Verify the archive with `pg_restore.exe --list <protected-backup-path>` and record a SHA-256 checksum. Store the dump and checksum in encrypted, access-controlled backup storage.
4. Provision a separate empty restore-rehearsal database. Set `PGHOST`, `PGPORT`, `PGUSER`, and `PGDATABASE` to that target, keep `PGSSLMODE=require`, and run `pg_restore.exe --password --no-owner --no-privileges --dbname <restore-rehearsal-db> <protected-backup-path>`. Enter the password at the prompt. Do not use `--clean` or `--create`; the destination must be new/empty.
5. Confirm restore completion, run `python manage.py showmigrations --plan` and read-only integrity/sample-row checks against the restored target, then run the applicable app smoke/test checks. Document elapsed recovery time and any errors. Preserve the source and backup until validation is signed off; delete only the rehearsal database under an explicit cleanup step.

### Commands, environment, and final pre-deploy checklist

The inspected Blueprint's commands are consistent with the tested setup. In the Render Dashboard/Blueprint, use backend as Root Directory if the Git repository root is its parent monorepo:

```sh
# Build
pip install -r requirements.txt && DJANGO_SETTINGS_MODULE=config.settings.build python manage.py collectstatic --noinput

# Historical paid-plan pre-deploy procedure (superseded; do not use for Free hosting)
python manage.py migrate --noinput

# Start
gunicorn config.wsgi:application --bind 0.0.0.0:$PORT --workers 2 --timeout 120
```

Before the first controlled deployment:

- [ ] Current plan uses Render Free + Neon + Upstash; use the staging gates in `render_neon_upstash_staging_plan.md`.
- [ ] Create new production Postgres and shared Redis/Key Value in the same region; use the internal DB/Redis URLs where available. Do not use local DB files or test-service URLs.
- [ ] Set Render environment secrets only in the Dashboard/environment group: `DJANGO_SECRET_KEY` and independent `JWT_SIGNING_KEY` (each at least 50 characters), `DATABASE_URL`, `REDIS_URL`. Set `DJANGO_SETTINGS_MODULE=config.settings.production`, `PYTHON_VERSION=3.14.6`, `DB_SSL_REQUIRE=true`, and `OFFLINE_POLICY_ISSUANCE_ENABLED=false`. Keep offline signing keys unset. Set exact custom hostnames only; leave CORS/CSRF lists empty unless a real browser origin requires them.
- [ ] Confirm the platform-provided `RENDER_EXTERNAL_HOSTNAME` is present and accepted by `ALLOWED_HOSTS`; configure the final custom API domain and TLS before sending clients.
- [ ] Resolve and test client-IP extraction against live Render headers, including forged XFF. Confirm `X-Forwarded-Proto=https`, host validation, HTTPS redirect, HSTS, cookies, and any CSRF/CORS browser flow through the actual edge.
- [ ] Take/retain a protected pre-migration backup as appropriate, inspect `migrate --plan`, and use the paid pre-deploy step. Never put migration in Gunicorn start.
- [ ] After service starts, verify HTTPS health/readiness, admin/static assets, authentication routes, logs, DB connection counts, Redis throttle behavior, and backup/restore rehearsal before inviting users.
- [ ] Keep application claims limited: file bytes, SD transfer, trusted STM32 proof, and offline policy are still unavailable.

Exact variable descriptions remain in the Environment variables table above. The service has not been deployed and no Render resource was created in this audit.

## Earlier verification history

- Ran `python run_backend_tests.py --base-url http://127.0.0.1:8000`: **151 tests passed, 2 skipped; all 6 HTTP smoke checks passed.** The suite used Django's isolated in-memory SQLite test database. The runner explicitly selects local settings and strips production DB, Redis, and signing-key environment variables from the test subprocess.
- Latest test output: [`test-reports/backend-test-report-20261031-005854.txt`](test-reports/backend-test-report-20261031-005854.txt).
- `python manage.py makemigrations --check --dry-run`: **No changes detected.**
- `DJANGO_SETTINGS_MODULE=config.settings.build python manage.py collectstatic --noinput`: passed; the static manifest exists. The latest repeat found 157 files unchanged and post-processed 408 assets. This did not access a database.
- `python manage.py check --deploy` with production settings and audit-only environment values: **no issues reported**. Assertions confirmed PostgreSQL engine selection, Redis cache backend, `DEBUG=False`, secure HTTPS/cookies, non-credentialed CORS, and independent JWT signing key. This check did not connect to PostgreSQL or Redis.
- New regression tests verify missing/SQLite PostgreSQL URLs, DB TLS opt-out, missing/separate JWT key, Redis config, HTTPS-only browser origins, and build settings not consuming provided production secrets.
- The earlier audit could not authenticate to local PostgreSQL and used mocked dependency outages. The later integration results above supersede that limitation.
- `showmigrations --plan` still shows seven unapplied migrations in the existing development DB: `accounts.0003_admin_bootstrap_lock`, `audit.0002_database_append_only`, `devices.0002_remove_device_public_id_redundant_index`, `hardware_auth.0002_auth_attempt_event`, `hardware_auth.0003_alter_authattempt_status`, `hardware_auth.0004_authattemptcapability`, and `offline_policies.0001_initial`. No migrations were applied locally.
- No Render deploy, production DB, production Redis, or real Render hostname/proxy validation was performed.

## Application and security review

### Settings, apps, routes, and middleware

`INSTALLED_APPS` includes Django admin/auth/contenttypes/sessions/messages/staticfiles, DRF, SimpleJWT plus its token blacklist app, CORS headers, and the HSS accounts, devices, hardware-auth, permissions, storage, offline-policy, audit, and health apps. The custom `accounts.User` model is set as `AUTH_USER_MODEL`.

The default DRF permission is `IsAuthenticated`; anonymous access is explicitly granted only where intended, including liveness/readiness, registration, and credential-based pre-auth. Admin mutations use the admin-role permission. Middleware includes Django security, WhiteNoise, CORS, sessions, common, CSRF, auth, messages, clickjacking protection, and request IDs. The CORS middleware is positioned before `CommonMiddleware`, as expected.

Routes cover health, login/refresh/logout/password change, registration/profile, devices, authentication attempts, file metadata/grants/content placeholder, offline policies, audit, Django admin, and admin account operations. Registration only creates a regular user. Device enrollment, assignment, and state changes are admin-only; device listing/detail are owner-scoped for ordinary accounts. File listing/detail and grants use owner or active-grant checks. Admins can administer metadata, but admin role alone does not grant file-content access.

### Local-development assumptions

- `manage.py` now requires `DJANGO_SETTINGS_MODULE` to be explicitly set; it no longer defaults to local settings.
- `config.settings.local` sets `DEBUG=True`, permits localhost/`0.0.0.0`/`testserver`, generates a per-process throwaway development key (no fixed key is committed), allows local HTTP CORS origins, and relaxes access-token lifetime. These settings must not be used by the deployed service.
- Base settings retain a SQLite fallback for explicitly selected local/build settings. `config.settings.production` now rejects missing/non-PostgreSQL `DATABASE_URL` before the service starts.
- Base settings use process-local `LocMemCache` whenever `REDIS_URL` is empty. Production's explicit Redis validator correctly refuses this configuration.
- The local database file exists and is ignored by Git. A `.dockerignore` now excludes environment files, databases, logs, test reports, static/media files, virtual environments, and local build artifacts from Docker contexts.
- The current desktop client is a native Python HTTP client. It does not use a browser CORS enforcement model.

### PostgreSQL and migrations

`DATABASE_URL` is parsed by `dj-database-url`; `psycopg2-binary==2.9.13` is pinned. Production now requires a PostgreSQL URL, verifies the resolved Django engine, and refuses `DB_SSL_REQUIRE=false`. Use a Render PostgreSQL URL, preferably the internal URL for a service in the same region, then verify the real URL/TLS behavior against that managed database. The development SQLite database has not been changed.

The migrations have no model drift according to `makemigrations --check`. The audit append-only migration's PostgreSQL trigger/function, `AdminBootstrapLock` data migration, and the remaining schema changes all ran successfully on the disposable PostgreSQL 16.15 database. PostgreSQL transaction/constraint and concurrency checks passed; details are in the latest verification section above. The existing development SQLite DB is still behind seven migrations, and no local migration was run. Before production, rehearse restore/rollback against a disposable managed-like PostgreSQL instance, then run migrations against the new production database through a controlled pre-deploy step. Do not reset the existing local DB to resolve its migration status.

Historical note: that original Render Postgres configuration used pre-deploy migrations. The current Free configuration removes `preDeployCommand`; see current instructions below. For Free hosting, migrations are operator-run once against Neon direct URL and never on startup.

### Secrets and credentials

No real Render database/Redis credentials or production signing keys were found in the Blueprint or `.env.example`. Render secrets use `sync: false`. Production requires `DJANGO_SECRET_KEY` and a distinct `JWT_SIGNING_KEY`, each at least 50 characters; the local-only key is now generated at runtime and `manage.py` requires explicit settings selection. Build settings generate a throwaway in-memory key and clear DB/Redis/offline-policy credentials before importing base settings.

Never commit or bundle: `DJANGO_SECRET_KEY`, `JWT_SIGNING_KEY`, PostgreSQL `DATABASE_URL` credentials, Redis `REDIS_URL` credentials, offline-policy signing private keys, production tokens, administrator passwords, `.env` files, database dumps, biometric templates, or test-user credentials. Do not put any of those in `portable_secure_app`, a PyInstaller spec, desktop executable, release ZIP, Docker image, logs, or `render.yaml`. Use Render environment secrets. The desktop app should receive only the public HTTPS backend URL and user-provided login credentials at runtime.

The example includes `SENTRY_DSN`, but the requirements/settings inspected do not configure a Sentry SDK; treat it as currently unused. `bootstrap_admin` supports an interactive password prompt, but also has a `--password` CLI option. Do not pass an administrator password as a command-line argument (it may be exposed in shell history/process arguments); use the interactive prompt in a controlled one-off shell.

### CORS, CSRF, and HTTPS

Production sets `SECURE_PROXY_SSL_HEADER` for Render's TLS-terminating proxy, enables HTTPS redirects, secure session/CSRF cookies, and one-year HSTS including subdomains/preload. It adds `RENDER_EXTERNAL_HOSTNAME` to `ALLOWED_HOSTS` and accepts additional comma-separated `DJANGO_ALLOWED_HOSTS`. Include any custom API domain explicitly and verify redirect behavior through the HTTPS edge.

`CORS_ALLOWED_ORIGINS` is exact-origin-only and empty by default; production sets `CORS_ALLOW_CREDENTIALS=False`. A native desktop client does not need CORS. If a browser client is introduced, allow only its exact HTTPS origin. Never use wildcard origins with credentials.

`CSRF_TRUSTED_ORIGINS` is environment-configured, but Render's hostname is not automatically added to this list. The desktop bearer-token API does not rely on browser cookies; Django admin is same-origin. Set exact HTTPS trusted origins only for browser flows that need them, including custom domains. Do not use HTTP origins in production.

### JWT, authentication, and revocation

SimpleJWT uses HS256, ten-minute access tokens, seven-day refresh tokens, refresh rotation, and blacklist-after-rotation. Production requires a distinct `JWT_SIGNING_KEY` of at least 50 characters. `SecureJWTAuthentication` checks user activity, token-version claims, and role claims against the live database. Password changes, role changes, deactivation, and explicit revoke-all increment/revoke token state. The token blacklist app is installed and its migrations are present.

Production uses the separate environment key; local settings may retain a development fallback. Document a rotation/revocation plan so Django framework signing and API token signing remain independently managed. Logout blacklists the submitted refresh token, but ordinary logout does not increment token version; a copied access token remains usable until its ten-minute expiry. The client clears its own local session, but this is not immediate server-side access-token revocation. This residual revocation window remains a product/security policy decision.

Login and registration have specific brute-force throttles. Production refuses startup unless a Redis URL and `RedisCache` are configured. Readiness now probes the configured cache with a short write/read/delete and returns 503 on failure. In addition, `get_client_ip()` selects `ips[-NUM_PROXIES]`; production hardcodes `NUM_PROXIES=1`. Verify the exact `X-Forwarded-For` chain produced by the chosen Render/Cloudflare setup and test spoofed-header cases before relying on IP throttles. A mismatch can merge clients behind one address or let a caller influence throttle identity.

### File/device and hardware API scope

Metadata, device registration, ownership and grants are database-authorized. No file bytes are returned: the content endpoint authorizes the caller and then returns `503 FILE_CONTENT_UNAVAILABLE`. This prevents a deployment from being mistaken for an operational secure file-storage service. Do not advertise SD/file-content protection or enable an alternate legacy transfer path.

Hardware-auth reports are stored with `verified=False`; the evidence classes are client assertion, host assertion, and unauthenticated serial. Attempt completion remains fail-closed. Offline-policy issuance remains disabled by default and has a code-owned prerequisite gate. Keep offline issuance/signing keys unset and disabled until the trusted-device protocol, authorization boundary, and actual hardware validation are completed.

### Health, static assets, and runtime

Liveness (`/api/v1/health/live/`) is anonymous and does not touch dependencies. Readiness (`/api/v1/health/ready/`) checks the database and configured cache and returns 503 when either fails. Render uses this readiness route.

WhiteNoise follows `SecurityMiddleware`, `STATIC_ROOT` is set, and compressed manifest storage is configured with `STORAGES`. The isolated build settings remove production credentials and collectstatic succeeded, producing the manifest. Deployed admin CSS still requires edge verification.

Installed Django is 6.0.6, which supports Python 3.12–3.14; Python 3.14.6 is pinned in `.python-version`, `render.yaml`, and the Dockerfile. The Docker image uses the isolated build settings for static collection.

## Current Render Free + Neon + Upstash instructions

The detailed, current hosting review and operational procedure is [render_neon_upstash_staging_plan.md](render_neon_upstash_staging_plan.md). It supersedes the earlier Render Postgres/Key Value and paid pre-deploy assumptions in the historical audit sections above.

Current Render build command:

```sh
pip install -r requirements.txt && DJANGO_SETTINGS_MODULE=config.settings.build python manage.py collectstatic --noinput
```

Current Render start command:

```sh
gunicorn config.wsgi:application --bind 0.0.0.0:$PORT --workers 2 --timeout 120
```

The Blueprint explicitly selects `plan: free`, checks `/api/v1/health/ready/`, and has no migration command. Runtime `DATABASE_URL` should be Neon pooled TLS URL; manual migration operator uses direct TLS URL. `REDIS_URL` should use Upstash native TCP `rediss://` protocol, not REST credentials. Production settings disable server-side cursors for PgBouncer transaction pooling and enable connection health checks. `CONN_MAX_AGE` remains 600 seconds pending Neon testing.

### Required environment variable names and purposes

- `DJANGO_SETTINGS_MODULE`: set production module for runtime.
- `DJANGO_SECRET_KEY`: Django secret; secret manager only.
- `JWT_SIGNING_KEY`: separate JWT signing secret.
- `DATABASE_URL`: Neon pooled TLS database URL for app runtime.
- `DB_SSL_REQUIRE`: must remain true.
- `REDIS_URL`: Upstash native TCP Redis TLS URL.
- `DJANGO_ALLOWED_HOSTS`: optional exact custom API hostnames; Render hostname is appended.
- `CSRF_TRUSTED_ORIGINS`: exact HTTPS browser/admin origins only when required.
- `CORS_ALLOWED_ORIGINS`: exact HTTPS browser origins; leave empty for native desktop client.
- `PYTHON_VERSION`: pinned build runtime.
- `RENDER_EXTERNAL_HOSTNAME`, `PORT`: platform-managed values.
- `NEON_DIRECT_DATABASE_URL`: operator-only migration variable; never add to Render runtime configuration.
- Keep `OFFLINE_POLICY_ISSUANCE_ENABLED` false; leave signing keys unset.

### Current blockers and recommendation

**NO-GO for production data or user traffic.** The user reports the staging checker passed five checks against the currently configured Neon and Upstash services (pooled/direct PostgreSQL TLS, Upstash TLS/PING, Redis set/get/delete, and Django production readiness); this report did not independently rerun them. A separate Neon staging branch has not yet been created or tested. Migration and restore/recovery, provider quotas/limits/cold resume, Render health behavior, HTTPS edge, forwarded client-IP chain/spoof handling, and secure headers remain staging gates. Free-tier sleep, ephemeral filesystem, absent shell/job/pre-deploy support, and backup/recovery terms must be accepted or addressed before production.

No development SQLite database was accessed or modified for this hosting configuration task.
