# Neon Staging Branch Isolation Plan

**State:** Instructions and local guards prepared only. No Neon branch was created, no provider was contacted, no database was changed, and no migration or deployment was run.

## Isolation and production-data warning

A Neon child branch has an isolated data state and its own compute endpoint, but it is created from a point-in-time parent snapshot. Current-data branches contain the parent’s current schema and data; Neon also offers schema-only and anonymized-data branch options. Changes on the child do not flow back to its parent. See [Neon branch management](https://neon.com/docs/manage/branches).

Before branch creation, classify the parent data. If it contains real user information, select **Schema only** for migration rehearsal or use an approved anonymization workflow. Do not select current data unless copying that information to staging is explicitly acceptable.

Neon documents that child branches normally inherit the parent’s PostgreSQL roles and passwords. New branch role passwords are available through branch protection, which current Neon documentation lists as a paid-plan feature. On Neon Free, do not assume credentials are isolated. Exact-host checks below reduce accidental misrouting in this project, but do not make an inherited password branch-specific. If separate credentials are mandatory, use an approach that provides them (for example, a separate staging project) before migration rehearsal.

## Manual Neon Console procedure

1. Open the existing Neon project. Confirm its identity and identify the **actual production branch** by name, parent/root status, and current production endpoint. Console-created projects commonly call the root `production`; API/CLI-created projects may call it `main`. Do not rely on the project's default-branch selection alone.
2. Select **Branches → New branch**. Explicitly select the confirmed production branch as **Parent branch**. Do not change the project default branch.
3. Choose a clear name such as `hss-staging-2026-10`. Select **Schema only** if staging does not need copied production rows. If realistic rows are essential and approved, use an anonymized-data flow. Choose current data only after data-owner approval.
4. Choose a suitable compute size and an expiration policy matching the intended staging lifetime. Do not accidentally leave an early auto-deletion on a branch needed for ongoing staging. Do not delete or reset an existing branch.
5. Create the branch, then record its branch ID/name, parent, creation point, and compute endpoint ID from its overview. Do not use Neon API/CLI in this plan.
6. On the new branch, select **Connect** and select that branch, its compute, intended database, and a staging role. Copy the pooled URL with pooling enabled; turn pooling off and copy the direct URL. Neon documents that pooled hostnames contain `-pooler`, while direct hostnames do not; the host identifies the selected compute endpoint. See [Neon connection setup](https://neon.com/docs/connect/connect-from-any-app) and [connection-string reference](https://neon.com/docs/cli/connection-string).
7. Compare both URL hostnames with the endpoint shown for the new staging branch. The pooled hostname should equal the direct hostname with `-pooler` inserted after the endpoint ID. Both URLs must use the staging database. Keep URLs only in ignored `staging.env` or a secret manager.

## Local `staging.env` changes

Only edit the ignored local `staging.env` after confirming the branch. Do not edit `.env.example`, production credentials, or Render environment values.

| Variable | Change to |
|---|---|
| `DATABASE_URL` | New branch's pooled URL (`-pooler` host). |
| `NEON_DIRECT_DATABASE_URL` | New branch's direct URL (no `-pooler`); operator-only for migration rehearsal. |
| `STAGING_EXPECTED_DB_NAME` | Exact selected Postgres database name. It may equal the production database name and is not branch identity by itself. |
| `STAGING_EXPECTED_NEON_POOLED_HOST` | Exact lower-case host from the staging pooled URL, without scheme, credentials, path, or port. |
| `STAGING_EXPECTED_NEON_DIRECT_HOST` | Exact lower-case host from the staging direct URL, without scheme, credentials, path, or port. |
| `STAGING_NEON_BRANCH_ID` | Branch ID from Neon Console, retained as an operator record. Current code does not claim to read this value from SQL. |
| `REDIS_URL` | Staging Upstash TLS URL; never a production Redis URL. |
| `DJANGO_SECRET_KEY`, `JWT_SIGNING_KEY` | Unique staging-only secrets; do not copy production keys. |

## Code guardrails

- `scripts/staging_connectivity_check.py` requires expected pooled and direct hostnames and refuses to connect unless the URLs exactly match those allow-listed values and form a pooled/direct pair. It also checks the expected database name and TLS.
- `config.settings.staging` is a fail-closed settings module for future tests/migration rehearsals. It requires the expected direct hostname and database name, rejects pooled URLs, and checks the `DATABASE_URL` host and database name before Django commands proceed.
- Neon branch ID is recorded for human verification. There is no SQL branch-ID check in this project. The machine guard uses the endpoint hostname copied from the staging branch’s Connect dialog. A matching database name alone is insufficient.
- The guard applies when using the checker or `config.settings.staging`; it cannot protect arbitrary SQL clients or commands run using other settings modules. Use only staging settings for branch tests and migration rehearsals.

## Future tests and migration rehearsal (not run)

For staging Django tests, set `DATABASE_URL` to `NEON_DIRECT_DATABASE_URL`, set `DJANGO_SETTINGS_MODULE=config.settings.staging`, and confirm the expected direct host/database first. Django's test runner creates a separate `test_...` database on the same staging endpoint; this can create and later remove that test database, so use only the dedicated staging branch. Never run that suite against production.

For a migration rehearsal, in a fresh PowerShell process:

1. Load staging-only values and visually confirm branch ID/name, parent branch, direct endpoint hostname, and database name in Neon Console.
2. Set `DJANGO_SETTINGS_MODULE=config.settings.staging` and `DATABASE_URL=$env:NEON_DIRECT_DATABASE_URL`.
3. Run `python manage.py check --deploy --settings=config.settings.staging`, `python manage.py showmigrations --settings=config.settings.staging`, and `python manage.py migrate --plan --settings=config.settings.staging`. These do not apply migrations. Review output and target identity.
4. Stop for explicit approval before any migration-application command. Never place migrations in Render build/start/restart.

Do not start the rehearsal solely because branch creation succeeded. First complete the approved connectivity check with the new host allow-list values.
