# Production Deployment Instructions (Render Free + Neon + Upstash)

See [render_neon_upstash_staging_plan.md](render_neon_upstash_staging_plan.md) for the provider compatibility audit, environment variable descriptions, manual migration procedure, staging gates, and current NO-GO decision.

For Neon staging branch setup and isolation guardrails, follow [NEON_STAGING_BRANCH_PLAN.md](NEON_STAGING_BRANCH_PLAN.md).

Render build command:

```sh
pip install -r requirements.txt && DJANGO_SETTINGS_MODULE=config.settings.build python manage.py collectstatic --noinput
```

Render start command:

```sh
gunicorn config.wsgi:application --bind 0.0.0.0:$PORT --workers 2 --timeout 120
```

The Render Free Blueprint deliberately has no pre-deploy migration command. Do not add migrations to startup. For a reviewed staging release, use a trusted operator workstation and the Neon direct TLS URL for one controlled `python manage.py migrate --noinput`; the web service uses the Neon pooled TLS URL. Configure Upstash using its native TCP `rediss://` URL, not its REST URL/token pair. Do not proceed to production until the staging integration and recovery gates pass.

## Staging connectivity test (approval required before execution)

The project currently uses these exact names:

- `DATABASE_URL`: Django's existing name for the runtime Neon pooled URL. The host must contain `-pooler`.
- `NEON_DIRECT_DATABASE_URL`: operator-only staging direct URL, added for this workflow. Django does not read this name automatically; the manual migration procedure maps it to `DATABASE_URL` in the migration process only.
- `REDIS_URL`: Django's existing RedisCache/throttling URL; use Upstash native TCP `rediss://`, not the REST endpoint/token pair.
- `STAGING_EXPECTED_DB_NAME`: non-secret guard used by the checker to compare both Neon URLs with the expected staging database.
- `STAGING_EXPECTED_NEON_POOLED_HOST`, `STAGING_EXPECTED_NEON_DIRECT_HOST`: exact staging branch endpoint hostnames. The checker refuses to connect if either URL targets another host.
- `STAGING_NEON_BRANCH_ID`: local operator record from Neon Console; it is not independently verified through SQL.

Copy `staging.env.example` to the ignored local file `staging.env`; fill it only from the Neon/Upstash consoles or a password manager. Set distinct staging-only Django/JWT keys. Do not paste credentials into chat, command-line arguments, or reports. In PowerShell from this directory, load the local file into the current process without printing values:

```powershell
Copy-Item staging.env.example staging.env
# Edit staging.env in a local editor, then:
Get-Content staging.env | ForEach-Object {
    if ($_ -match '^\s*([^#=\s]+)\s*=(.*)$') {
        [Environment]::SetEnvironmentVariable($matches[1], $matches[2].Trim(), 'Process')
    }
}
```

Before running the check, confirm in the Neon console that both URLs point to the disposable staging branch, set both exact expected endpoint hostnames, and copy its exact database name to `STAGING_EXPECTED_DB_NAME`. The checker uses SELECT-only SQL for both pooled and direct PostgreSQL URLs, verifies negotiated client-to-endpoint TLS through psycopg2/libpq `connection.info.ssl_in_use` and verifies database identity, PINGs Upstash, sets/gets/deletes one uniquely named temporary Redis key, then checks the local Django readiness route against the pooled URL and Redis. It preserves `verify-full`/`verify-ca` URL modes and refuses weaker modes; an absent `sslmode` is upgraded to `require`. It suppresses connection exception details to prevent credentials leaking. It does not migrate, flush, reset, or delete database data. TLS active is not the same claim as certificate/hostname verified: that additionally depends on the chosen `sslmode`.

**Do not run until the user approves the provider connection test.** After approval, the command is:

```powershell
.\.venv\Scripts\python.exe scripts\staging_connectivity_check.py
```

Do not use `run_backend_tests.py` for this staging connection test: its documented runner isolates local tests and does not test Neon or Upstash.

## Manual Neon migration procedure (separate; not run)

Migrations are not part of the connectivity check. After explicit approval for a migration, confirm a disposable staging target and recovery point, load staging variables, and perform a second operator confirmation of the exact Neon database name. In a dedicated PowerShell process only, map the direct URL to the setting Django already consumes:

```powershell
$env:DATABASE_URL = $env:NEON_DIRECT_DATABASE_URL
```

For migration rehearsal, set `DJANGO_SETTINGS_MODULE=config.settings.staging` and map the staging direct URL to `DATABASE_URL`. Run `python manage.py showmigrations --settings=config.settings.staging` and `python manage.py migrate --plan --settings=config.settings.staging`; the staging settings reject pooled URLs and any host/database mismatch. Review target identity and plan, then stop for explicit approval before any migration application. Never put migrations in Render build/start/restart or run this with local/production settings. No migration command has been run.
