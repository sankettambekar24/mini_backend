# Hybrid Secure Storage System — Backend

Fresh Django + Django REST Framework + Simple JWT backend for the Hybrid Secure Storage System project, adhering to `Secure_Storage_Backend_Architecture_v2.md`.

## Features Implemented

### Phase 1: Foundation Baseline
- **Custom User Model** (`apps.accounts.User`): UUID primary keys, role-based (`ADMIN` and `USER`), safe profiles excluding passwords. Standard self-registration strictly grants `USER`.
- **Authentication & Simple JWT**: Token obtain (`/api/v1/auth/token/`), token refresh with rotation (`/api/v1/auth/token/refresh/`), token blacklist on logout (`/api/v1/auth/logout/`), password change with verification.
- **Health Checks** (`apps.health`): `/api/v1/health/live/` (liveness without DB) and `/api/v1/health/ready/` (readiness with DB check).
- **Audit Logging Baseline** (`apps.audit`): Append-only security event logger.
- **Initial Schema & Stubs** for future phases (`devices`, `hardware_auth`, `permissions`, `storage`).
- **Standardized Error Responses & Correlation IDs** (`common.exceptions`, `common.middleware`).

### Phase 2: Accounts, Roles, Brute-Force & Token Invalidation
- **Admin Bootstrap Command** (`apps/accounts/management/commands/bootstrap_admin.py`):
  - Strict single-admin policy enforced with database row-locking (`select_for_update()` inside atomic transaction).
  - Validates password strength (min length, complexity, common passwords) and does not echo passwords in output or logs.
  - Rejects attempts if an administrator already exists.
- **Brute-Force & Credential Stuffing Protection** (`common.throttling`):
  - IP-based rate limiting (`auth_login_ip`: 10/min) and compound username+IP rate limiting (`auth_login_user`: 5/min).
  - Rate limits trigger a `LOGIN_LOCKED_OUT` audit event with IP, username, and cooldown duration.
  - Constant error responses on authentication failure: non-existent accounts and wrong passwords return identical generic 401 errors, defeating username harvesting.
- **Immediate Stateless Access Token Revocation** (`apps.authentication.authentication.SecureJWTAuthentication`):
  - Solves the stateless JWT vulnerability by tracking `token_version` on the `User` model.
  - Token claims include `token_version` and `role`.
  - On password change, role change, account deactivation, or full logout, `token_version` is incremented.
  - Existing access tokens are immediately rejected across all distributed instances on their next request (`TOKEN_REVOKED` or `ROLE_CHANGED`).
  - Inactive accounts are immediately rejected with `USER_INACTIVE`.
- **JWT claims and refresh lifecycle**: protected access tokens must carry integer `token_version` and recognized `role` claims, both checked against the current active database user on each request. Missing, malformed, stale, or mismatched claims are rejected. Refresh tokens are checked against current user/version/role before rotation; rotation blacklists the prior refresh token. Logout blacklists only the caller's supplied refresh token. Access JWTs remain valid until expiry unless `revoke_all=true` or an account/password/role change increments `token_version`.
- **Standardized Audit Event Catalog & Secret Sanitization** (`apps.audit`):
  - Standardized enum `AuditEventType`: `LOGIN_SUCCESS`, `LOGIN_FAILED`, `LOGIN_LOCKED_OUT`, `LOGOUT`, `TOKEN_REFRESH`, `PASSWORD_CHANGED`, `PASSWORD_CHANGE_FAILED`, `USER_REGISTERED`, `ADMIN_BOOTSTRAP`, `ADMIN_USER_CREATED`, `ADMIN_USER_UPDATED`, `USER_ACTIVATED`, `USER_DEACTIVATED`, `USER_ROLE_CHANGED`.
  - Automatic recursive redaction of sensitive keys (`password`, `pin`, `token`, `secret`, `biometric`, `key`) from audit metadata.
  - Audit endpoints strictly restricted to read-only (`GET` list and detail); all modification methods (`POST`/`PUT`/`PATCH`/`DELETE`) return 405 Method Not Allowed.
- **IP Proxy Spoofing Defense** (`common.security.get_client_ip`):
  - Rejects untrusted `X-Forwarded-For` injection by default.
  - In production behind trusted proxies (e.g., Render), parses proxy hops based on configured `NUM_PROXIES`.
- **Shared production throttling**: production settings require a valid `redis://` or `rediss://` `REDIS_URL` and Django's Redis cache backend. Missing or malformed configuration prevents production settings from loading. Redis runtime failures are allowed to fail the request instead of silently switching to a process-local cache. Local settings and isolated tests continue to use LocMemCache.

### Phase 3: Device Registry & Authentication Attempts
- Device enrollment, owner assignment, and lifecycle transitions are administrator-only; device owners can view their own devices.
- Device statuses follow `PENDING -> ACTIVE|REVOKED|LOST`, `ACTIVE -> REVOKED|LOST`, and `LOST -> REVOKED`. `REVOKED` and `LOST` cannot be reactivated; replace a lost device with a new enrollment.
- Auth attempts are created by an authenticated user for their own active device. The server issues the UUID and five-minute expiry and fixes the required factor list.
- Stage events require contract version 1, a unique event UUID, the bound device UUID, and one factor name. Duplicate event IDs, duplicate factor reports, expired attempts, and user/device mismatches are rejected.
- Events are explicitly unverified. `FACE` is classified as a host assertion, `FINGERPRINT` as unauthenticated serial evidence, and `PIN` as a client assertion. No factor event can set `verified=true`, and the completion endpoint returns `FACTOR_VERIFICATION_UNAVAILABLE`; this backend does not grant a hardware-authenticated session.
- Security-critical device/attempt state changes and their audit rows are atomic. A failed strict audit write aborts the state change.

## Phase 3 API contract (version 1)

All routes below are under `/api/v1/` and require a JWT except device enrollment/status/assignment, which additionally require an administrator role.

| Route | Request | Behavior |
|---|---|---|
| `GET /devices/` | — | Admin sees all devices; user sees owned devices. |
| `POST /devices/` | `device_label`, `device_public_id`, optional `protocol_version`, optional `owner_user` UUID | Admin creates a `PENDING` device. The ID is an identifier, not device attestation. |
| `GET /devices/{device_id}/` | — | Admin or owner reads device metadata. |
| `POST /devices/{device_id}/assign/` | `owner_user` UUID or `null` | Admin assigns/unassigns a pending device. |
| `POST /devices/{device_id}/status/` | `status`: `ACTIVE`, `REVOKED`, or `LOST` | Admin requests a permitted lifecycle transition. |
| `POST /auth-attempts/` | `device_id` UUID | Creates a server-ID’d attempt with a five-minute expiry and required factors `PIN`, `FACE`, `FINGERPRINT`. |
| `GET /auth-attempts/{attempt_id}/` | — | Owner or admin reads the attempt and its factor reports. |
| `POST /auth-attempts/{attempt_id}/events/` | `contract_version: 1`, `event_id` UUID, `device_id` UUID, `factor` | Records one unverified report for that factor. It is not authentication proof. |
| `POST /auth-attempts/{attempt_id}/complete/` | `device_id` UUID | Fails closed with `FACTOR_VERIFICATION_UNAVAILABLE` until actual verifiers are integrated. |
| `POST /auth-attempts/{attempt_id}/cancel/` | `device_id` UUID | Cancels an unexpired pending attempt. |

Typical errors use the existing `error.code` envelope: `DEVICE_USER_MISMATCH`, `DEVICE_INACTIVE`, `ATTEMPT_USER_MISMATCH`, `ATTEMPT_DEVICE_MISMATCH`, `ATTEMPT_EXPIRED`, `REPLAYED_EVENT`, `DUPLICATE_FACTOR`, `INVALID_ATTEMPT_STATE`, and `FACTOR_VERIFICATION_UNAVAILABLE`.

Successful attempt creation returns `201` with `id`, `user_id`, `device_id`, `status`, `required_factors`, `created_at`, `expires_at`, `completed_at`, `failure_code`, and `events`. An accepted event returns `201` with that attempt representation and `reported_event: {id, event_id, factor, evidence_class, verified: false}`. Device responses include `id`, `device_label`, `device_public_id`, `owner_user_id`, `status`, `protocol_version`, timestamps, and `revoked_at`. Error responses use `{ "error": { "code": "...", "message": "..." } }`.

No liveness detection, hardware attestation, cryptographic device proof, encrypted SD-card format, or successful multi-factor session issuance is implemented by this API.

### Phase A: Offline-policy foundation (fail-closed)

The backend now has a versioned `OfflinePolicy` record, exact-file UUID scope records, lifecycle/revocation metadata, an RS256 JWS signing and online verification service, and a versioned policy metadata API. The signing private key is read only from secure server configuration; configure `OFFLINE_POLICY_SIGNING_KEY_ID`, `OFFLINE_POLICY_SIGNING_PRIVATE_KEY`, and the corresponding `OFFLINE_POLICY_VERIFYING_KEYS_JSON` map through the deployment secret manager. No key material belongs in source control or logs. `OFFLINE_POLICY_ISSUER`, `OFFLINE_POLICY_AUDIENCE`, and `OFFLINE_POLICY_MAX_SECONDS` constrain the token contract. The issuance switch defaults off.

Issuance also has code-owned prerequisite gates and is **disabled in this phase even if the configuration switch is enabled**. Device proof, file-content authorization at the physical read boundary, reliable trusted expiry, and verified authentication evidence do not exist. Phase 1 provides metadata-only grants; it does not authorize or expose file bytes. The signer/verifier foundation is not an offline verifier: its online verification checks current Django registry/revocation state and uses server time. It cannot establish trustworthy time or device identity for a disconnected client.

| Route | Contract |
|---|---|
| `POST /api/v1/auth/preauth/` | Accepts primary credentials and `device_id`; creates a bound pending AuthAttempt and returns its representation plus a random short-lived attempt capability. It does not return access or refresh JWTs. Client-reported factors remain unverified. |
| `GET /api/v1/offline-policies/` | Authenticated metadata list, restricted to the caller's policies (admins may list all). No signed policy token or file content is returned. |
| `POST /api/v1/offline-policies/` | Returns `503 OFFLINE_POLICY_ISSUANCE_DISABLED`; creates no policy. Client-supplied file requests are not accepted as grants. |
| `GET /api/v1/offline-policies/{id}/` | Authenticated owner/admin metadata only; no token, file bytes, or key material. |
| `POST /api/v1/offline-policies/{id}/revoke/` | Owner/admin revocation with strict audit logging. |

The pre-auth capability is sent in `X-Auth-Attempt-Capability` only to the same attempt's detail, event, and cancel endpoints. It is stored server-side as a digest and is not accepted by normal JWT endpoints, policy APIs, or `/complete/`. It is a narrowly scoped bearer credential, **not** device proof or factor evidence. `/complete/` remains fail-closed with `FACTOR_VERIFICATION_UNAVAILABLE`.

`OfflinePolicy` lifecycle states are `PREPARED`, `ISSUED`, `REVOKED`, `EXPIRED`, and `SUPERSEDED`; policy family/version, schema version, nonce, user/device binding, file UUID scopes, issue/expiry, signing key ID, and revocation metadata are represented in the model. These are backend records and a signing contract only. There is no offline file-open API, key-release API, encrypted SD format, secure-element integration, or claim that stored SD content is encrypted.

Audit writes fail closed by default. Auth/account mutations, token refresh/logout/password changes, device operations, AuthAttempt changes, and admin bootstrap pair audit writes with database transactions so audit failure rolls back the state change. SQLite and PostgreSQL migrations install database triggers that reject audit-row updates/deletes; actor-user references also prevent hard deletion of audited users. Non-critical callers can opt into best-effort logging explicitly; no current security-state mutation does so.

### Phase 1: Django file authorization foundation (metadata only)

These routes are versioned under `/api/v1/` and require a normal Django JWT unless the route is admin-only. File IDs are server-generated `StoredFileMetadata` UUIDs. Legacy filename paths, usernames, device public IDs, and client role fields are not authorization credentials.

| Route | Request | Authorization and behavior |
|---|---|---|
| `GET /files/` | — | Owner sees own non-deleted metadata; an active `LIST` grant makes metadata appear in the list; admin sees registry metadata. |
| `POST /files/metadata/` | `owner_user_id`, `display_name` | Admin-only metadata registration. The API does not accept a content locator, size, encryption version, device, owner role, or path. New records start with no content and format version 0. |
| `GET /files/{file_id}/` | — | Owner, admin (metadata only), or active `READ` grantee may see metadata. A `LIST` grant alone does not permit detail lookup. |
| `GET /files/{file_id}/content/` | — | Checks owner or active `READ` grant, then returns `503 FILE_CONTENT_UNAVAILABLE`. No bytes are read or returned. Admin role alone does not grant content access. |
| `GET /files/{file_id}/grants/` | — | Owner or admin only; lists grants for this file, including revoked/expired grant metadata. |
| `POST /files/{file_id}/grants/` | `subject_user_id`, `permission` (`LIST` or `READ`), optional future `expires_at` | Owner or admin creates a grant. `resource_id` and `granted_by` are assigned server-side. Regranting a revoked/expired scope reactivates its existing row and is audited. |
| `POST /files/{file_id}/grants/{grant_id}/revoke/` | empty body | Owner or admin revokes a grant; changes and strict audit writes are atomic. |

No upload, download, SD transfer, encryption, or key-release route is enabled. Metadata names are display labels, not paths; path separators and control characters are rejected. Grant `READ` currently provides metadata authorization only because content storage is unavailable. Existing legacy file grants are not imported into Django; the Companion App's `/api/files/...` contract remains separate, and its legacy session/authentication routes continue to fail closed with HTTP 409. See `../docs/hardware_protocol_inventory.md` and `../docs/encrypted_sd_storage_design.md` for the unverified STM32 read boundary and host plaintext limits.

---

## Local Setup

### 1. Requirements
- Python 3.11+
- Virtual environment recommended

### 2. Installation
```powershell
pip install -r requirements.txt
```

### 3. Environment Configuration
Copy `.env.example` to `.env`:
```powershell
Copy-Item .env.example .env
```
Default local settings use SQLite (`config.settings.local`).
The backend does not automatically load `.env`; set the settings module in the PowerShell session before running commands:

```powershell
$env:DJANGO_SETTINGS_MODULE = "config.settings.local"
```

### 4. Database Migrations
```powershell
python manage.py migrate
```

### 5. Running Automated Tests
Run the complete test suite:
```powershell
python manage.py test tests --verbosity=2
```

### 6. Bootstrapping Designated Administrator
Run the dedicated bootstrap management command:
```powershell
python manage.py bootstrap_admin --username admin_master
```
*(You will be prompted securely for a strong password without echoing).*

### 7. Development Server
```powershell
python manage.py runserver 8000
```

---

## Administrator Account Management & Disaster Recovery

### Single-Admin Policy
The architecture dictates a single designated administrator.
- A shared database lock serializes bootstrap, manager-based superuser creation, and administrator API mutations.
- A second administrator is rejected; demotion or deactivation of the last administrator is blocked.
- Self-registration `/api/v1/auth/register/` strictly creates `USER` accounts only. Django admin account writes are disabled; audited APIs and `bootstrap_admin` are supported account-management paths.

### Disaster Recovery: Admin Password Reset
If the administrator password is lost, an authorized host operator with console access can execute:
```powershell
python manage.py changepassword <admin_username>
```
The project-managed `changepassword` command validates the password, updates its hash, increments `token_version`, and writes an audit event in the same transaction. Prior access and refresh tokens are rejected on their next use. The command does not add a refresh token to the blacklist table; version enforcement rejects it during refresh.

---

## Production Deployment (Render Free + Neon + Upstash)

The maintained configuration and migration steps are documented in [`DEPLOYMENT_RENDER.md`](DEPLOYMENT_RENDER.md) and [`render_neon_upstash_staging_plan.md`](render_neon_upstash_staging_plan.md). Render Free uses no automatic migration command: migrations must be reviewed and run once from a trusted operator workstation against Neon’s direct URL. Runtime traffic should use Neon’s pooled URL. Use Upstash’s native TCP `rediss://` URL. Provider URLs and secrets must be entered only in secret/environment settings and never committed.
