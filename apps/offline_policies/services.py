"""JWS signing, online registry verification, issuance gate, and revocation."""

import base64
import binascii
import hmac
import json
from datetime import timezone as datetime_timezone
from uuid import UUID

import jwt
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.audit.services import record_audit_event
from apps.offline_policies.models import (
    OfflinePolicy,
    OfflinePolicyFileScope,
    OfflinePolicyScope,
    OfflinePolicyStatus,
)


POLICY_SCHEMA = "hsss.offline-policy.v1"
POLICY_TYP = "application/vnd.hybrid-secure-storage.offline-policy+jws"
POLICY_ALGORITHM = "RS256"
REQUIRED_POLICY_CLAIMS = {
    "iss", "aud", "iat", "nbf", "exp", "jti", "policy_id", "policy_version",
    "nonce", "sub", "device_id", "device_key_id", "schema", "schema_version",
    "max_offline_seconds", "files",
}

# These are deliberately code-owned false in Phase A. Environment flags cannot
# assert that missing security controls have been implemented.
UNMET_ISSUANCE_PREREQUISITES = (
    "verified_device_proof",
    "enforced_file_grants",
    "reliable_trusted_expiry",
    "verified_authentication_evidence",
)


class OfflinePolicyError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def policy_issuance_enabled():
    """The config switch is necessary but never sufficient in Phase A."""
    return bool(settings.OFFLINE_POLICY_ISSUANCE_ENABLED and not UNMET_ISSUANCE_PREREQUISITES)


def require_policy_issuance_enabled():
    if not policy_issuance_enabled():
        raise OfflinePolicyError("OFFLINE_POLICY_ISSUANCE_DISABLED")


def _private_key_configuration():
    key_id = str(settings.OFFLINE_POLICY_SIGNING_KEY_ID or "").strip()
    private_key = str(settings.OFFLINE_POLICY_SIGNING_PRIVATE_KEY or "")
    if not key_id or not private_key.strip():
        raise OfflinePolicyError("OFFLINE_POLICY_SIGNING_CONFIGURATION_MISSING")
    return key_id, private_key.replace("\\n", "\n")


def _verifying_key_configuration():
    raw = str(settings.OFFLINE_POLICY_VERIFYING_KEYS_JSON or "").strip()
    if not raw:
        raise OfflinePolicyError("OFFLINE_POLICY_VERIFICATION_CONFIGURATION_MISSING")
    try:
        keys = json.loads(raw, object_pairs_hook=_reject_duplicate_pairs)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise OfflinePolicyError("OFFLINE_POLICY_VERIFICATION_CONFIGURATION_INVALID") from exc
    if not isinstance(keys, dict) or not keys or any(
        not isinstance(kid, str) or not kid.strip() or not isinstance(key, str) or not key.strip()
        for kid, key in keys.items()
    ):
        raise OfflinePolicyError("OFFLINE_POLICY_VERIFICATION_CONFIGURATION_INVALID")
    public_keys = {}
    for key_id, pem in keys.items():
        try:
            public_key = serialization.load_pem_public_key(pem.encode("utf-8"))
        except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
            raise OfflinePolicyError("OFFLINE_POLICY_VERIFICATION_CONFIGURATION_INVALID") from exc
        if not isinstance(public_key, RSAPublicKey):
            raise OfflinePolicyError("OFFLINE_POLICY_VERIFICATION_CONFIGURATION_INVALID")
        public_keys[key_id] = public_key
    return public_keys


def sign_policy(policy, *, issued_at=None, expires_at=None):
    """Create a JWS for a prepared policy using only server configuration.

    Keep the prerequisite gate at the signing boundary as well as the API
    boundary so internal callers and directly created model rows cannot bypass
    the fail-closed issuance policy.
    """
    require_policy_issuance_enabled()
    key_id, private_key = _private_key_configuration()
    issued_at = issued_at or policy.issued_at
    expires_at = expires_at or policy.expires_at
    if not issued_at or not expires_at:
        raise OfflinePolicyError("OFFLINE_POLICY_TIMES_REQUIRED")
    if not policy.device_key_id:
        raise OfflinePolicyError("OFFLINE_POLICY_DEVICE_KEY_REQUIRED")
    if policy.schema_version != 1:
        raise OfflinePolicyError("UNSUPPORTED_POLICY_VERSION")

    issued_at = issued_at.astimezone(datetime_timezone.utc)
    expires_at = expires_at.astimezone(datetime_timezone.utc)
    duration = int((expires_at - issued_at).total_seconds())
    if duration <= 0 or duration > policy.max_offline_seconds:
        raise OfflinePolicyError("OFFLINE_POLICY_INVALID_EXPIRY")
    max_seconds = int(settings.OFFLINE_POLICY_MAX_SECONDS)
    if policy.max_offline_seconds <= 0 or policy.max_offline_seconds > max_seconds:
        raise OfflinePolicyError("OFFLINE_POLICY_MAX_DURATION_INVALID")

    grouped = {}
    for row in policy.file_scopes.select_related("file").order_by("file_id", "scope"):
        grouped.setdefault(str(row.file_id), []).append(row.scope)
    if not grouped:
        raise OfflinePolicyError("OFFLINE_POLICY_FILES_REQUIRED")
    claims = {
        "iss": settings.OFFLINE_POLICY_ISSUER,
        "aud": settings.OFFLINE_POLICY_AUDIENCE,
        "iat": int(issued_at.timestamp()),
        "nbf": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
        "jti": str(policy.policy_id),
        "policy_id": str(policy.policy_id),
        "policy_version": policy.policy_version,
        "nonce": str(policy.nonce),
        "sub": str(policy.user_id),
        "device_id": str(policy.device_id),
        "device_key_id": policy.device_key_id,
        "schema": POLICY_SCHEMA,
        "schema_version": policy.schema_version,
        "max_offline_seconds": policy.max_offline_seconds,
        "files": [
            {"file_id": file_id, "scopes": sorted(set(scopes))}
            for file_id, scopes in sorted(grouped.items())
        ],
    }
    try:
        token = jwt.encode(
            claims,
            private_key,
            algorithm=POLICY_ALGORITHM,
            headers={"typ": POLICY_TYP, "kid": key_id},
        )
    except Exception as exc:
        # Do not include cryptographic exception details, keys, or claims.
        raise OfflinePolicyError("OFFLINE_POLICY_SIGNING_FAILED") from exc
    return token, key_id


def _reject_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _decode_json_segment(segment):
    if not segment or "=" in segment:
        raise OfflinePolicyError("MALFORMED_POLICY")
    try:
        padded = segment + "=" * (-len(segment) % 4)
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
        if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != segment:
            raise ValueError("non-canonical base64url")
        value = json.loads(decoded.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except (ValueError, UnicodeDecodeError, binascii.Error, json.JSONDecodeError) as exc:
        raise OfflinePolicyError("MALFORMED_POLICY") from exc
    if not isinstance(value, dict):
        raise OfflinePolicyError("MALFORMED_POLICY")
    return value


def _uuid_claim(value, name):
    if not isinstance(value, str):
        raise OfflinePolicyError("MALFORMED_POLICY")
    try:
        parsed = UUID(value)
    except (ValueError, TypeError, AttributeError) as exc:
        raise OfflinePolicyError("MALFORMED_POLICY") from exc
    if str(parsed) != value.lower():
        raise OfflinePolicyError("MALFORMED_POLICY")
    return parsed


def _validate_claims(claims, *, now):
    if set(claims) != REQUIRED_POLICY_CLAIMS:
        raise OfflinePolicyError("MALFORMED_POLICY")
    if claims.get("schema") != POLICY_SCHEMA or claims.get("schema_version") != 1:
        raise OfflinePolicyError("UNSUPPORTED_POLICY_VERSION")
    if claims.get("iss") != settings.OFFLINE_POLICY_ISSUER:
        raise OfflinePolicyError("INVALID_POLICY_ISSUER")
    audience = claims.get("aud")
    if audience != settings.OFFLINE_POLICY_AUDIENCE:
        raise OfflinePolicyError("INVALID_POLICY_AUDIENCE")
    for name in ("iat", "nbf", "exp", "policy_version", "max_offline_seconds", "schema_version"):
        if isinstance(claims.get(name), bool) or not isinstance(claims.get(name), int):
            raise OfflinePolicyError("MALFORMED_POLICY")
    if claims["policy_version"] < 1 or claims["max_offline_seconds"] < 1:
        raise OfflinePolicyError("MALFORMED_POLICY")
    if claims["max_offline_seconds"] > int(settings.OFFLINE_POLICY_MAX_SECONDS):
        raise OfflinePolicyError("OFFLINE_POLICY_MAX_DURATION_INVALID")
    now_ts = int(now.timestamp())
    if claims["iat"] > now_ts or claims["nbf"] > now_ts:
        raise OfflinePolicyError("POLICY_NOT_YET_VALID")
    if claims["nbf"] != claims["iat"]:
        raise OfflinePolicyError("MALFORMED_POLICY")
    if claims["exp"] <= claims["iat"] or claims["exp"] - claims["iat"] > claims["max_offline_seconds"]:
        raise OfflinePolicyError("OFFLINE_POLICY_INVALID_EXPIRY")
    policy_id = _uuid_claim(claims.get("policy_id"), "policy_id")
    if claims.get("jti") != str(policy_id):
        raise OfflinePolicyError("MALFORMED_POLICY")
    _uuid_claim(claims.get("nonce"), "nonce")
    _uuid_claim(claims.get("sub"), "sub")
    _uuid_claim(claims.get("device_id"), "device_id")
    if not isinstance(claims.get("device_key_id"), str) or not claims["device_key_id"].strip():
        raise OfflinePolicyError("MALFORMED_POLICY")
    files = claims.get("files")
    if not isinstance(files, list) or not files:
        raise OfflinePolicyError("MALFORMED_POLICY")
    seen_files = set()
    for item in files:
        if not isinstance(item, dict) or set(item) != {"file_id", "scopes"}:
            raise OfflinePolicyError("MALFORMED_POLICY")
        file_id = str(_uuid_claim(item.get("file_id"), "file_id"))
        if file_id in seen_files:
            raise OfflinePolicyError("MALFORMED_POLICY")
        seen_files.add(file_id)
        scopes = item.get("scopes")
        if (
            not isinstance(scopes, list)
            or not scopes
            or any(not isinstance(scope, str) for scope in scopes)
            or any(scope not in OfflinePolicyScope.values for scope in scopes)
            or len(scopes) != len(set(scopes))
        ):
            raise OfflinePolicyError("MALFORMED_POLICY")
    return policy_id


@transaction.atomic
def _mark_policy_expired(policy, *, at):
    policy = OfflinePolicy.objects.select_for_update().get(pk=policy.pk)
    if policy.status == OfflinePolicyStatus.ISSUED and policy.expires_at and policy.expires_at <= at:
        policy.status = OfflinePolicyStatus.EXPIRED
        policy.save(update_fields=["status", "updated_at"])
        record_audit_event(
            "OFFLINE_POLICY_EXPIRED",
            "EXPIRED",
            actor_user=policy.user,
            device=policy.device,
            safe_metadata={"policy_id": str(policy.policy_id), "policy_version": policy.policy_version},
            strict=True,
        )
    return policy


def verify_policy(token, *, expected_user_id, expected_device_id, now=None):
    """Verify a JWS and its current server-side registry state.

    This is an online/backend verifier. It does not provide trusted offline time,
    device proof, file-grant enforcement, or file access.
    """
    keys = _verifying_key_configuration()
    if not isinstance(token, str) or not token or len(token) > 65536:
        raise OfflinePolicyError("MALFORMED_POLICY")
    parts = token.split(".")
    if len(parts) != 3:
        raise OfflinePolicyError("MALFORMED_POLICY")
    header = _decode_json_segment(parts[0])
    claims_untrusted = _decode_json_segment(parts[1])
    if set(header) != {"alg", "kid", "typ"} or header.get("alg") != POLICY_ALGORITHM or header.get("typ") != POLICY_TYP:
        raise OfflinePolicyError("UNSUPPORTED_POLICY_FORMAT")
    key_id = header.get("kid")
    if not isinstance(key_id, str) or key_id not in keys:
        raise OfflinePolicyError("UNKNOWN_POLICY_SIGNING_KEY")
    try:
        claims = jwt.decode(
            token,
            keys[key_id],
            algorithms=[POLICY_ALGORITHM],
            options={
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
                "verify_aud": False,
                "verify_iss": False,
            },
        )
    except jwt.InvalidTokenError as exc:
        raise OfflinePolicyError("INVALID_POLICY_SIGNATURE") from exc
    if claims != claims_untrusted:
        raise OfflinePolicyError("MALFORMED_POLICY")
    now = now or timezone.now()
    policy_id = _validate_claims(claims, now=now)

    try:
        policy = OfflinePolicy.objects.select_related("user", "device").get(
            policy_id=policy_id,
            policy_version=claims["policy_version"],
        )
    except OfflinePolicy.DoesNotExist as exc:
        raise OfflinePolicyError("POLICY_NOT_REGISTERED") from exc
    if policy.status == OfflinePolicyStatus.REVOKED:
        raise OfflinePolicyError("POLICY_REVOKED")
    if policy.status == OfflinePolicyStatus.SUPERSEDED:
        raise OfflinePolicyError("POLICY_SUPERSEDED")
    if policy.status == OfflinePolicyStatus.EXPIRED:
        raise OfflinePolicyError("POLICY_EXPIRED")
    if policy.status != OfflinePolicyStatus.ISSUED:
        raise OfflinePolicyError("POLICY_NOT_ISSUED")

    if str(policy.user_id) != str(expected_user_id) or claims["sub"] != str(policy.user_id):
        raise OfflinePolicyError("POLICY_USER_MISMATCH")
    if str(policy.device_id) != str(expected_device_id) or claims["device_id"] != str(policy.device_id):
        raise OfflinePolicyError("POLICY_DEVICE_MISMATCH")
    if not policy.user.is_active:
        raise OfflinePolicyError("POLICY_USER_INACTIVE")
    if policy.device.status != "ACTIVE" or policy.device.owner_user_id != policy.user_id:
        raise OfflinePolicyError("POLICY_DEVICE_INACTIVE")
    if (
        claims["nonce"] != str(policy.nonce)
        or claims["device_key_id"] != policy.device_key_id
        or key_id != policy.signing_key_id
        or claims["schema_version"] != policy.schema_version
        or claims["max_offline_seconds"] != policy.max_offline_seconds
        or not policy.issued_at
        or not policy.expires_at
        or claims["iat"] != int(policy.issued_at.timestamp())
        or claims["exp"] != int(policy.expires_at.timestamp())
        or claims["jti"] != str(policy.policy_id)
        or not policy.signed_policy
        or not hmac.compare_digest(policy.signed_policy, token)
    ):
        raise OfflinePolicyError("POLICY_RECORD_MISMATCH")

    actual_files = {}
    for row in OfflinePolicyFileScope.objects.filter(policy=policy).order_by("file_id", "scope"):
        actual_files.setdefault(str(row.file_id), []).append(row.scope)
    token_files = {
        item["file_id"]: sorted(item["scopes"])
        for item in claims["files"]
    }
    if {key: sorted(set(value)) for key, value in actual_files.items()} != token_files:
        raise OfflinePolicyError("POLICY_SCOPE_MISMATCH")

    if policy.expires_at <= now or claims["exp"] <= int(now.timestamp()):
        policy = _mark_policy_expired(policy, at=now)
        raise OfflinePolicyError("POLICY_EXPIRED")
    return policy


@transaction.atomic
def revoke_policy(*, policy_id, actor, reason):
    try:
        policy = OfflinePolicy.objects.select_for_update().get(pk=policy_id)
    except OfflinePolicy.DoesNotExist as exc:
        raise OfflinePolicyError("POLICY_NOT_FOUND") from exc
    if policy.status not in (OfflinePolicyStatus.PREPARED, OfflinePolicyStatus.ISSUED):
        raise OfflinePolicyError("POLICY_INVALID_STATE")
    policy.status = OfflinePolicyStatus.REVOKED
    policy.revoked_at = timezone.now()
    policy.revoked_by = actor
    policy.revocation_reason = reason
    policy.save(update_fields=["status", "revoked_at", "revoked_by", "revocation_reason", "updated_at"])
    record_audit_event(
        "OFFLINE_POLICY_REVOKED",
        "SUCCESS",
        actor_user=actor,
        device=policy.device,
        safe_metadata={"policy_id": str(policy.policy_id), "policy_version": policy.policy_version,
                       "reason": reason},
        strict=True,
    )
    return policy
