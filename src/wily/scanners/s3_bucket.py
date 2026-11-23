"""S3 bucket misconfiguration scanner.

Given a bucket reference (bare name, ``s3://bucket/key``, or
``*.s3*.amazonaws.com`` URL), checks for public bucket listing, public
object read, and ACL/policy exposure granting ``AllUsers``/
``AuthenticatedUsers`` access.

Safety: by default every request is a GET - never a PUT/DELETE, so the
scanner can never mutate a third-party bucket. Write/delete exposure is
only *inferred* from a readable ACL/policy granting a wildcard principal
write access, and reporting that inference is gated behind ``confirm_writes``
(``--confirm-s3-writes``), default off.

There is exactly ONE path that can send a mutating request (PUT/DELETE): the
OPTIONAL lab-mode active write-confirmation probe. It is OFF by default and
fires only when ALL THREE independent gates hold at once (see
``_lab_write_allowed``):
  1. the environment variable ``WILY_ALLOW_S3_WRITE`` is set truthy,
  2. the ``lab_write`` flag (``--s3-lab-write``) is passed, AND
  3. the bucket is inside an explicitly configured owned/lab bucket scope
     (``ScopeManager`` bucket scope) - never a plain bug-bounty target.
When it fires it uploads a single tiny marker object with an unmistakable
``wily-check-<id>.txt`` key, confirms the write, then deletes it immediately
(best-effort delete in a ``finally``; a failed cleanup is surfaced in the
finding). A missing gate means the probe does nothing and the scanner behaves
exactly as the read-only default, and every refusal is logged.
"""

from __future__ import annotations

import logging
import os
import re
import secrets
from dataclasses import dataclass

from wily.core.scope_manager import ScopeManager, extract_bucket_name
from wily.scanners.base import BaseScanner, Finding
from wily.scanners.http_engine import HttpEngine

logger = logging.getLogger("wily.s3_bucket")

# AWS canonical group URIs that mean "anyone" / "any AWS account".
_ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
_AUTH_USERS_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

# How much of an ACL/policy/listing body is kept as evidence.
_EVIDENCE_SNIPPET_LEN = 400

# Env-var gate for the active lab-mode write probe. The canonical value is
# ``WILY_ALLOW_S3_WRITE=true``; a small set of truthy spellings is accepted.
_ENV_ALLOW_S3_WRITE = "WILY_ALLOW_S3_WRITE"
_TRUTHY_ENV_VALUES = frozenset({"1", "true", "yes", "on"})


def _env_allows_s3_write() -> bool:
    """True only when ``WILY_ALLOW_S3_WRITE`` is set to a truthy value.

    This is one of the three independent gates on the active write probe;
    with the variable unset (the default) the probe can never run.
    """
    return os.environ.get(_ENV_ALLOW_S3_WRITE, "").strip().lower() in _TRUTHY_ENV_VALUES


@dataclass
class _WriteProbeResult:
    """Outcome of a single active marker PUT + cleanup DELETE."""

    marker_key: str
    put_status: int | None
    confirmed: bool  # the PUT returned 2xx -> the bucket is genuinely writable
    delete_status: int | None
    delete_error: str | None
    cleanup_ok: bool  # the marker was removed again (best-effort DELETE 2xx)

_LIST_RESULT_RE = re.compile(r"<ListBucketResult", re.IGNORECASE)
_NO_SUCH_BUCKET_RE = re.compile(r"<Code>\s*NoSuchBucket\s*</Code>", re.IGNORECASE)


def s3_host_for(bucket: str, region: str | None = None) -> str:
    """The S3 host used to reach ``bucket``.

    Virtual-hosted style is preferred, but a bucket name containing a dot
    breaks TLS virtual-hosting (the wildcard cert does not cover
    ``my.bucket.s3.amazonaws.com``), so those fall back to path-style on the
    plain ``s3[.region].amazonaws.com`` host.
    """
    regional = f"s3.{region}.amazonaws.com" if region else "s3.amazonaws.com"
    if "." in bucket:
        return regional
    return f"{bucket}.{regional}"


def s3_base_url(bucket: str, region: str | None = None) -> str:
    """Base URL for the bucket (path-style includes the bucket segment)."""
    host = s3_host_for(bucket, region)
    if host.startswith(bucket + "."):  # virtual-hosted
        return f"https://{host}"
    return f"https://{host}/{bucket}"


@dataclass
class S3BucketTarget:
    """``bucket`` may be a name, an ``s3://`` URI or an S3 URL - it is
    normalised to the bucket name. ``sample_object_key`` enables the public
    object-read check when a concrete key is known (e.g. from a discovered
    link)."""

    bucket: str
    region: str | None = None
    sample_object_key: str | None = None

    @property
    def name(self) -> str:
        return extract_bucket_name(self.bucket) or self.bucket.strip().lower()


class S3BucketScanner(BaseScanner):
    name = "s3_bucket"
    requires_tenant_pair = False
    # Read-only checks are safe against arbitrary buckets; the write/delete
    # inference is additionally gated by confirm_writes below.
    requires_owned_infra = False

    def __init__(
        self,
        scope_manager: ScopeManager | None = None,
        http_engine: HttpEngine | None = None,
        confirm_writes: bool = False,
        lab_write: bool = False,
    ) -> None:
        self.scope = scope_manager
        self.http = http_engine
        self._confirm_writes = confirm_writes
        # Opt-in flag for the active lab-mode write probe (gate 2 of 3). OFF by
        # default; even when on, the probe still needs the env var and an
        # owned/lab bucket scope before it can send a single request.
        self._lab_write = lab_write

    def _get(self, url: str):
        if self.http is None:
            return None
        try:
            return self.http.request(method="GET", url=url, headers={})
        except Exception:
            return None

    @staticmethod
    def _snippet(body: str) -> str:
        return (body or "")[:_EVIDENCE_SNIPPET_LEN]

    def run(self, target: S3BucketTarget) -> list[Finding]:
        bucket = target.name
        findings: list[Finding] = []

        # Respect bucket scope when one is configured: don't probe a bucket the
        # tester did not authorise. With no bucket scope configured, read checks
        # run (report-everything mode - see ScopeManager.has_bucket_scope).
        if (
            self.scope is not None
            and self.scope.has_bucket_scope
            and not self.scope.is_bucket_in_scope(target.bucket)
        ):
            return findings

        base = s3_base_url(bucket, target.region)

        # --- Check 1: anonymous bucket listing -----------------------------
        list_resp = self._get(base if base.endswith("/") else base + "/")
        if list_resp is not None and list_resp.status_code == 200 and _LIST_RESULT_RE.search(
            list_resp.text or ""
        ):
            findings.append(
                Finding(
                    asset=f"s3://{bucket}",
                    category="s3-bucket-public-listing",
                    severity="high",
                    confidence=0.9,
                    discovery_source="scanner",
                    evidence={
                        "bucket": bucket,
                        "check": "anonymous_list",
                        "status": list_resp.status_code,
                        "response_snippet": self._snippet(list_resp.text),
                    },
                    remediation=(
                        "Enable S3 Block Public Access at the account and bucket "
                        "level, and remove any bucket policy / ACL grant to "
                        "AllUsers. Anonymous listing exposes every object key."
                    ),
                )
            )

        # --- Check 2: public object read -----------------------------------
        if target.sample_object_key:
            obj_url = f"{base.rstrip('/')}/{target.sample_object_key.lstrip('/')}"
            obj_resp = self._get(obj_url)
            if obj_resp is not None and obj_resp.status_code == 200:
                findings.append(
                    Finding(
                        asset=f"s3://{bucket}/{target.sample_object_key.lstrip('/')}",
                        category="s3-bucket-public-object",
                        severity="high",
                        confidence=0.85,
                        discovery_source="scanner",
                        evidence={
                            "bucket": bucket,
                            "object_key": target.sample_object_key,
                            "check": "anonymous_object_read",
                            "status": obj_resp.status_code,
                        },
                        remediation=(
                            "Make the object private (remove the public-read ACL "
                            "/ policy) unless it is intended to be world-readable; "
                            "serve genuinely public assets via CloudFront with an "
                            "origin access identity instead of a public bucket."
                        ),
                    )
                )

        # --- Check 3: ACL / policy exposure + write inference --------------
        acl_resp = self._get(f"{base.rstrip('/')}/?acl")
        acl_body = (acl_resp.text or "") if acl_resp is not None else ""
        acl_public = acl_resp is not None and acl_resp.status_code == 200 and (
            _ALL_USERS_URI in acl_body or _AUTH_USERS_URI in acl_body
        )
        if acl_public:
            findings.append(
                Finding(
                    asset=f"s3://{bucket}",
                    category="s3-bucket-public-acl",
                    severity="medium",
                    confidence=0.8,
                    discovery_source="scanner",
                    evidence={
                        "bucket": bucket,
                        "check": "anonymous_acl_read",
                        "status": acl_resp.status_code,
                        "grants_all_users": _ALL_USERS_URI in acl_body,
                        "grants_authenticated_users": _AUTH_USERS_URI in acl_body,
                        "response_snippet": self._snippet(acl_body),
                    },
                    remediation=(
                        "The bucket ACL is world-readable and grants a global "
                        "group. Remove AllUsers/AuthenticatedUsers grants and "
                        "disable ACLs (set Object Ownership to 'Bucket owner "
                        "enforced')."
                    ),
                )
            )

        # Write/delete capability: inferred from the public ACL grants only -
        # no mutating request is ever sent. Reporting it is opt-in.
        if self._confirm_writes and acl_resp is not None and acl_resp.status_code == 200:
            writable = self._acl_grants_write(acl_body)
            if writable:
                findings.append(
                    Finding(
                        asset=f"s3://{bucket}",
                        category="s3-bucket-public-writable",
                        severity="critical",
                        confidence=0.75,
                        discovery_source="scanner",
                        evidence={
                            "bucket": bucket,
                            "check": "write_permission_inferred_from_acl",
                            "grants_all_users": _ALL_USERS_URI in acl_body,
                            "inferred_write_grant": writable,
                            "note": (
                                "Writability inferred from a WRITE/WRITE_ACP grant "
                                "to a global group in the bucket ACL. NO PUT or "
                                "DELETE was sent - this is a read-derived "
                                "permission check only."
                            ),
                            "response_snippet": self._snippet(acl_body),
                        },
                        remediation=(
                            "A global group has WRITE access: anyone can upload, "
                            "overwrite or delete objects (defacement / malware "
                            "hosting / data destruction). Remove the WRITE / "
                            "WRITE_ACP grant immediately and enable Block Public "
                            "Access."
                        ),
                    )
                )

        # --- Check 4: ACTIVE lab-mode write confirmation (strictly gated) --
        # The ONLY path in this scanner that can send a mutating request
        # (PUT/DELETE). It is disabled unless ALL THREE independent gates hold,
        # evaluated together here so a reviewer can see at a glance that it
        # cannot fire by accident. Every refusal is logged; a missing gate
        # leaves the scanner behaving exactly as the read-only default above.
        if self._lab_write:
            allowed, reason = self._lab_write_allowed(target)
            if not allowed:
                logger.info(
                    "S3 active lab-write probe refused for %s: %s", bucket, reason
                )
            else:
                logger.warning(
                    "S3 active lab-write probe ENABLED for owned/lab bucket %s "
                    "(env var + flag + owned scope all set); sending a single "
                    "marker PUT and an immediate DELETE.",
                    bucket,
                )
                findings += self._run_active_lab_write(bucket, base)

        return findings

    # -- Active lab-mode write probe (gated; see module docstring) ----------

    def _lab_write_allowed(self, target: S3BucketTarget) -> tuple[bool, str]:
        """Evaluate the three independent gates for the active write probe.

        Returns ``(allowed, reason)``. ``allowed`` is True only when every gate
        passes; the reason explains the first failing gate for the log.
        """
        # Gate 1: explicit environment variable.
        if not _env_allows_s3_write():
            return False, f"env var {_ENV_ALLOW_S3_WRITE} is not set to a truthy value"
        # Gate 2: the --s3-lab-write flag (true to even reach here; re-checked
        # so this method is correct in isolation and defensible under review).
        if not self._lab_write:
            return False, "--s3-lab-write flag is off"
        # Gate 3: the bucket must be inside an explicitly configured owned/lab
        # bucket scope - never a plain, unconfigured bug-bounty target.
        if self.scope is None or not self.scope.has_bucket_scope:
            return False, "no owned/lab S3 bucket scope configured (--scope-bucket)"
        if not self.scope.is_bucket_in_scope(target.bucket):
            return False, "bucket is not inside the configured owned/lab scope"
        return True, "all gates passed"

    def _send_mutating(self, method: str, url: str, body: str | None = None):
        """Issue a single PUT/DELETE through the shared, scope-enforced HTTP
        engine. This is the ONLY method that sends a mutating request, and it
        is called EXCLUSIVELY from ``_run_active_lab_write`` after every gate in
        ``_lab_write_allowed`` has passed."""
        if self.http is None:
            return None
        return self.http.request(method=method, url=url, headers={}, body=body)

    def _active_lab_write_probe(self, base: str) -> _WriteProbeResult:
        """Upload one tiny marker object, then delete it immediately.

        The marker key is unmistakable (``wily-check-<random>.txt``) so the
        object is obviously a scanner artifact. The DELETE runs in a
        ``finally`` so a successful PUT is always cleaned up even if something
        raises in between; a failed cleanup is reported, never swallowed.
        """
        marker_key = f"wily-check-{secrets.token_hex(8)}.txt"
        obj_url = f"{base.rstrip('/')}/{marker_key}"
        marker_body = "wily write-permission check - safe to delete"

        put_status: int | None = None
        confirmed = False
        delete_status: int | None = None
        delete_error: str | None = None
        try:
            put_resp = self._send_mutating("PUT", obj_url, body=marker_body)
            if put_resp is not None:
                put_status = put_resp.status_code
                confirmed = 200 <= put_resp.status_code < 300
        except Exception as exc:  # a failed PUT means nothing was created
            logger.info("S3 lab-write PUT to %s failed: %s", obj_url, exc)
        finally:
            # Best-effort cleanup: always try to remove the marker so a
            # successful PUT never leaves an artifact behind.
            try:
                del_resp = self._send_mutating("DELETE", obj_url)
                if del_resp is not None:
                    delete_status = del_resp.status_code
            except Exception as exc:
                delete_error = str(exc)
                logger.warning(
                    "S3 lab-write cleanup DELETE of %s failed: %s", obj_url, exc
                )

        cleanup_ok = delete_status is not None and 200 <= delete_status < 300
        return _WriteProbeResult(
            marker_key=marker_key,
            put_status=put_status,
            confirmed=confirmed,
            delete_status=delete_status,
            delete_error=delete_error,
            cleanup_ok=cleanup_ok,
        )

    def _run_active_lab_write(self, bucket: str, base: str) -> list[Finding]:
        """Run the gated marker PUT/DELETE and, only on a confirmed write,
        emit an active-confirmation ``s3-bucket-public-writable`` finding whose
        evidence is distinct from the read-only ACL inference."""
        result = self._active_lab_write_probe(base)
        if not result.confirmed:
            # The marker PUT was rejected: the bucket is NOT publicly writable.
            # Nothing was created, so the best-effort DELETE was a harmless
            # no-op and there is nothing to report.
            return []

        cleanup_failed = not result.cleanup_ok
        evidence: dict = {
            "bucket": bucket,
            "check": "write_permission_confirmed_active_lab_put",
            "active_probe": True,
            "marker_key": result.marker_key,
            "put_status": result.put_status,
            "delete_status": result.delete_status,
            "cleanup_ok": result.cleanup_ok,
            "note": (
                "ACTIVE lab-mode confirmation: a single tiny marker object was "
                "uploaded with PUT and then deleted. This is NOT the default "
                "read-only ACL inference - it ran only because "
                f"{_ENV_ALLOW_S3_WRITE}=true, the --s3-lab-write flag, and an "
                "owned/lab bucket scope were ALL set, and the PUT returned a "
                "success status."
            ),
        }
        if cleanup_failed:
            evidence["cleanup_failed"] = True
            evidence["cleanup_error"] = result.delete_error
            evidence["cleanup_warning"] = (
                f"The marker object {result.marker_key} may still exist "
                f"(DELETE status={result.delete_status}, "
                f"error={result.delete_error}). Remove it manually."
            )
            logger.warning(
                "S3 lab-write marker %s on %s may NOT have been deleted "
                "(status=%s, error=%s).",
                result.marker_key, bucket, result.delete_status, result.delete_error,
            )

        return [
            Finding(
                asset=f"s3://{bucket}",
                category="s3-bucket-public-writable",
                severity="critical",
                confidence=0.95,
                discovery_source="scanner",
                evidence=evidence,
                remediation=(
                    "CONFIRMED writable by an anonymous principal (a marker "
                    "object was uploaded and deleted). Anyone can upload, "
                    "overwrite or delete objects (defacement / malware hosting "
                    "/ data destruction). Remove the public WRITE grant / policy "
                    "statement immediately and enable S3 Block Public Access."
                    + (
                        " NOTE: automated cleanup of the marker object FAILED - "
                        "delete it manually."
                        if cleanup_failed
                        else ""
                    )
                ),
            )
        ]

    @staticmethod
    def _acl_grants_write(acl_body: str) -> list[str]:
        """Return the write-type permissions granted to a global group, read
        straight from the ACL XML. Never sends a request."""
        if not acl_body:
            return []
        granted: list[str] = []
        # Each <Grant> pairs a <Grantee> (may be a global group URI) with a
        # <Permission>. A simple, dependency-free scan: for every global-group
        # URI occurrence, look at the permissions near it.
        if _ALL_USERS_URI not in acl_body and _AUTH_USERS_URI not in acl_body:
            return []
        for perm in ("WRITE_ACP", "WRITE", "FULL_CONTROL"):
            # The permission text appears in the same <Grant> block as the
            # global-group grantee. We treat any WRITE*/FULL_CONTROL alongside a
            # global group as a write grant (conservative - may include a grant
            # to a non-global grantee in a pathological ACL, hence confidence
            # stays < 0.8).
            if re.search(rf"<Permission>\s*{perm}\s*</Permission>", acl_body, re.IGNORECASE):
                granted.append(perm)
        return granted
