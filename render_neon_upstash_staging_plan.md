# HSS Staging Plan: Render Free, Neon Free, Upstash Free

**Updated:** 2026-10-31  
**Status:** Configuration prepared; provider integrations not yet live-tested.  
**Recommendation:** **NO-GO for production data or user traffic.** Proceed only with a disposable staging Neon branch/database and Upstash database, then re-evaluate.

## Scope and evidence

This plan is based on the checked-in Django settings, `render.yaml`, health endpoint, requirements, previous local PostgreSQL 16.15/Redis 7 integration, current provider documentation, and the user's report that the staging checker passed all five connection/readiness checks. That reported check covers the currently configured Neon branch endpoints; no separate staging branch was created or changed during this task. No branch was created, no database data was modified, no migration ran, and no Render deployment occurred. The development SQLite database was not opened or modified in this task.

Local evidence remains: PostgreSQL 16.15 and Redis 7 integration passed previously; 151 backend tests passed with zero skipped; six PostgreSQL-backed HTTP smoke checks passed; 44 migrations were applied to the isolated local test database. These do not establish Neon or Upstash compatibility.

## Configuration reviewed and updated

- Production settings require `DATABASE_URL`, require PostgreSQL, and enforce `DB_SSL_REQUIRE=true`. `dj-database-url` parses Render-injected `DATABASE_URL`; when TLS is required, PostgreSQL connections use `sslmode=require`. Neon requires TLS and documents connection URLs with `sslmode=require` and optionally `channel_binding=require`.
- Runtime `DATABASE_URL` should be Neon’s pooled URL (Neon endpoint hostname includes `-pooler`). Neon uses PgBouncer transaction pooling. Production now sets `DISABLE_SERVER_SIDE_CURSORS=True`, which Django documents as necessary for server-side cursor use with transaction pooling. `CONN_HEALTH_CHECKS=True` checks reused connections once per request when the DB is used. Existing `CONN_MAX_AGE=600` remains; verify this with real Neon cold wake/reconnect behavior. A 10-minute persistent client connection is a configuration choice, not evidence that a Neon session stays active or that its limits are adequate.
- Migration/admin commands must use Neon’s direct endpoint URL, not the pooled endpoint. Neon explicitly recommends direct connections for schema migrations and pooler transaction mode restricts session features.
- Production requires `REDIS_URL`; RedisCache and the DRF throttles use the same configured cache. Upstash’s native TCP URL is compatible in principle with redis-py and Django RedisCache when copied from the Upstash TCP connection details using `rediss://`. The REST endpoint/token URL is **not** a Redis URL and is not accepted by this configuration. The URL scheme enables TLS. Actual Upstash authentication, cache operations, TTL/delete, throttling counters, reconnect and quota failure behavior remain unverified.
- `render.yaml` now explicitly selects `plan: free`, has no `preDeployCommand`, and keeps migrations out of Gunicorn startup. Free web services do not support pre-deploy commands, shell/SSH or one-off jobs. Free services spin down after 15 minutes idle, have ephemeral filesystem, and may restart; custom domains and managed TLS are supported. The service binds to `$PORT` and uses Render’s HTTPS termination.
- Build command: `pip install -r requirements.txt && DJANGO_SETTINGS_MODULE=config.settings.build python manage.py collectstatic --noinput`
- Start command: `gunicorn config.wsgi:application --bind 0.0.0.0:$PORT --workers 2 --timeout 120`
- Health path remains `/api/v1/health/ready/`; it performs a DB `SELECT 1` and Redis cache write/read/delete. It may wake Neon compute and consumes Upstash operations. Measure cold-start latency and health-check behavior on actual services before relying on it.

Provider references: [Neon connection URLs and TLS](https://neon.com/docs/connect/connect-from-any-app), [Neon pooling](https://neon.com/docs/connect/connection-pooling), [Django transaction pooling and cursors](https://docs.djangoproject.com/en/6.0/ref/databases/#transaction-pooling-and-server-side-cursors), [Upstash Redis on Render](https://upstash.com/docs/redis/quickstarts/render), [Upstash compatibility](https://upstash.com/docs/redis/overall/compatibility), [Render Free limitations](https://render.com/docs/free), [Render pre-deploy commands](https://render.com/docs/deploys), [Render shell access](https://render.com/docs/ssh).

## Proxy and HTTPS review

Production trusts `X-Forwarded-Proto: https` for Django secure-request detection, redirects HTTP to HTTPS, enables secure session/CSRF cookies and HSTS, and restricts configured CORS/CSRF origins to HTTPS. `RENDER_EXTERNAL_HOSTNAME` is appended to `ALLOWED_HOSTS`. These settings are statically consistent with Render’s TLS edge, but redirect, cookie, hostname and CSRF behavior need verification through the actual public staging URL.

Render says inbound traffic passes through Cloudflare and Render load balancers, and directs apps to use `X-Forwarded-For` for client address. Current `get_client_ip()` chooses `ips[-NUM_PROXIES]`; production sets `NUM_PROXIES=1`, which selects the rightmost XFF value. Render’s public documentation does not establish that this particular one-hop selection is correct for this app’s real request chain. A forged XFF test and comparison with Render/Cloudflare trace data are required before relying on IP-based login throttles. Do not change to trusting `CF-Connecting-IP` without confirming Render actually forwards that header and overwrites client input. [Render client IP guidance](https://render.com/articles/how-render-handles-ddos-attacks).

## Environment variables (names and descriptions only)

| Name | Purpose |
|---|---|
| `DJANGO_SETTINGS_MODULE` | Runtime settings module; use `config.settings.production`. |
| `DJANGO_SECRET_KEY` | High-entropy Django framework secret; secret manager only. |
| `JWT_SIGNING_KEY` | Independent high-entropy JWT signing key, separate from Django secret. |
| `DATABASE_URL` | Render runtime Neon **pooled** PostgreSQL URL with TLS; secret. |
| `DB_SSL_REQUIRE` | Must be `true`; production fails closed if disabled. |
| `REDIS_URL` | Upstash native TCP Redis URL using `rediss://`; secret; do not use REST URL/token pair. |
| `DJANGO_ALLOWED_HOSTS` | Optional comma-separated custom API hostnames; Render hostname is appended automatically. |
| `CSRF_TRUSTED_ORIGINS` | Exact HTTPS origins only when browser/admin flows need them. |
| `CORS_ALLOWED_ORIGINS` | Exact HTTPS browser client origins only; leave empty for native desktop bearer-token client. |
| `OFFLINE_POLICY_ISSUANCE_ENABLED` | Keep false. |
| `OFFLINE_POLICY_SIGNING_KEY_ID`, `OFFLINE_POLICY_SIGNING_PRIVATE_KEY`, `OFFLINE_POLICY_VERIFYING_KEYS_JSON` | Leave unset; offline issuance prerequisites are not complete. |
| `PYTHON_VERSION` | Pinned runtime version from the current Render configuration. |
| `RENDER_EXTERNAL_HOSTNAME`, `PORT` | Supplied by Render; not user-defined secrets. |
| `NEON_DIRECT_DATABASE_URL` | Operator workstation only for controlled migration operations; Neon **direct** URL with TLS. Do not add to the Render web service. |

Never commit or print secret values. Neon examples may contain `channel_binding=require`; retain Neon’s copied query parameters unless an actual psycopg2/libpq compatibility test demonstrates a problem. The deployed requirements currently pin psycopg2-binary. Do not remove TLS parameters to troubleshoot.

## Safe first migration and subsequent schema changes

Render Free offers no shell, one-off job, or pre-deploy command. Do not place `migrate` in `startCommand`, a build command, or automatic restart path. Use a trusted operator workstation with this repository revision and a securely injected direct Neon URL. Confirm the target Neon project/branch/database identity in its console first; never use the local SQLite file or a development DB URL.

1. Create a dedicated staging Neon project/branch/database and Upstash DB. Use no real customer data.
2. In a clean PowerShell session at the backend project root, securely load staging environment values from a password manager/secret store. Set `DJANGO_SETTINGS_MODULE=config.settings.production`, `DATABASE_URL` to the **direct** staging Neon URL, `DB_SSL_REQUIRE=true`, `REDIS_URL` to the staging Upstash TCP TLS URL, and valid staging-only `DJANGO_SECRET_KEY` and separate `JWT_SIGNING_KEY`. Configure the expected HTTPS host/origin values as needed. Do not save these values in source control or shell history.
3. Before applying anything, verify Django reports PostgreSQL engine and the intended database name without printing credentials. Run `python manage.py check --deploy`, `python manage.py showmigrations`, and `python manage.py migrate --plan`. Stop if host/database identity is unexpected, any check fails, or the plan includes an unreviewed operation.
4. Take/confirm a Neon restore point or branch-based recovery point according to the current plan’s documented retention. Neon branching is a recovery aid, not a tested backup until restore has been rehearsed.
5. Run `python manage.py migrate --noinput` exactly once for the reviewed staging release from the operator workstation. Confirm migration status and basic application read/write/readiness. Do not run concurrently from multiple operators.
6. Configure Render’s runtime `DATABASE_URL` with the matching **pooled** staging URL and `REDIS_URL` with the matching Upstash `rediss://` TCP URL. Deploy only after staging integration gates below pass.
7. For each future schema release, review migration SQL/plan and backup/recovery first. Use expand/contract changes compatible with both currently running and next app code. Run the migration once from the operator workstation against the direct URL, then deploy the code. For destructive changes, split removal into a later release after data/code no longer depend on it. If the migration fails, stop; inspect state, restore/recover only into a separate target as rehearsed, and do not blindly rerun partially completed operations.

Free plan has no integrated migration serialization or rollback runner. Protect the direct URL carefully; use a DB role with only required privileges where feasible, and rotate credentials if exposed. Maintain a written operator log with release revision, migration names, time, and success/failure—never credentials.

## Staging verification gates

Before a production go decision, actually provision only when authorized and test:

1. Verify Neon direct and pooled URLs, TLS handshake, `SELECT current_database(), version()`, `channel_binding` handling, and role privileges with current pinned `psycopg2`/libpq.
2. Apply all reviewed migrations on a disposable Neon staging branch via direct URL; repeat the app test suite and PostgreSQL constraints/transaction checks there.
3. Run app reads/writes and concurrent requests through the pooled URL. Exercise queryset iteration, transactions, advisory/session features if any, long requests, and pool saturation. Confirm server-side cursors remain disabled.
4. Measure persistent connection count for two Gunicorn workers, rollout overlap, Neon pooler client/server limits, `CONN_MAX_AGE=600`, restart/cold resume and recovery after a stale connection.
5. Verify Upstash TCP (`rediss://`) authentication, ping, Django cache set/get/delete/TTL, DRF throttle behavior, concurrent limits, reconnect, timeout, unavailable Redis, and free quota exhaustion behavior. Check current free tier quota and billing/overage behavior; do not assume generous or unlimited availability.
6. Exercise `/api/v1/health/live/` and `/api/v1/health/ready/` with healthy dependencies, each dependency unavailable, and after Neon idle/cold wake. Confirm Render health probe timeout/restart behavior does not cause a restart loop.
7. Through a Render staging HTTPS URL, test HTTP redirect, `X-Forwarded-Proto`, secure cookies, HSTS, `ALLOWED_HOSTS`, CSRF/CORS, real client IP, forged XFF, and login throttle identity. Keep exact evidence with secrets removed.
8. Rehearse Neon backup/branch restore into a separate target, verify application reads and constraints, and document recovery time and owner. Free-tier data durability/retention and provider quota/limits must be confirmed in current account terms before real data.

## Remaining blockers and decision

- **The user reports the staging connectivity checker passed all five checks** (Neon pooled/direct TLS, Upstash TLS/PING, Redis set/get/delete, Django readiness). This task did not independently rerun them. A new staging branch has not yet been created/tested; quotas, limits, cold resume, failover, branch isolation and failure behavior remain unverified.
- **No Render service was deployed.** Public HTTPS, host, health-probe and forwarded headers are unverified.
- **XFF hop interpretation remains unresolved.** The hardcoded one-hop extraction must be checked against actual Render traffic and a spoofed-header test.
- **No Neon migration or restore rehearsal has run.** Free tier recovery and retention need confirmation before storing non-disposable data.
- **Render Free is best effort:** the service sleeps after inactivity, local files are ephemeral, and it has no jobs/shell/pre-deploy migration support. Upstash/Neon free quotas and service behavior may not meet reliability requirements; confirm actual plan limits and overage/suspension policy.
- **Product limitations remain:** file contents, trusted STM32 hardware evidence and offline-policy issuance are not production-ready (see the main readiness report).

**GO/NO-GO:** **NO-GO for production deployment or real user data.** Conditional **GO for an isolated staging trial** once test-only Neon and Upstash resources are supplied by the project owner. Reassess production only after every live gate passes and the free-tier reliability/data recovery tradeoffs are accepted.
