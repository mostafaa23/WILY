"""Phase 3: S3 bucket misconfiguration scanner.

A scripted fake HTTP engine (keyed on the request URL) drives every case, so
there is no real network or AWS call. The scanner only ever sends GETs, which
these tests assert.
"""

from dataclasses import dataclass

import pytest

from wily.core.scope_manager import ScopeManager
from wily.scanners.s3_bucket import S3BucketScanner, S3BucketTarget, s3_base_url, s3_host_for

_ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"

_LIST_XML = (
    '<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    "<Name>victim</Name><Contents><Key>secret.txt</Key></Contents></ListBucketResult>"
)

_ACL_READ_ONLY = (
    "<AccessControlPolicy><AccessControlList><Grant>"
    f"<Grantee><URI>{_ALL_USERS}</URI></Grantee><Permission>READ</Permission>"
    "</Grant></AccessControlList></AccessControlPolicy>"
)

_ACL_WRITABLE = (
    "<AccessControlPolicy><AccessControlList><Grant>"
    f"<Grantee><URI>{_ALL_USERS}</URI></Grantee><Permission>WRITE</Permission>"
    "</Grant></AccessControlList></AccessControlPolicy>"
)


@dataclass
class _Resp:
    status_code: int
    text: str = ""


class _FakeHttp:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def request(self, method, url, headers=None, body=None):
        self.calls.append((method, url))
        for pattern, resp in self.routes.items():
            if pattern in url:
                return resp
        return _Resp(404, "<Error><Code>NoSuchKey</Code></Error>")


def test_host_and_url_helpers():
    assert s3_host_for("victim") == "victim.s3.amazonaws.com"
    # A dotted bucket name falls back to path-style.
    assert s3_host_for("my.victim") == "s3.amazonaws.com"
    assert s3_base_url("victim") == "https://victim.s3.amazonaws.com"
    assert s3_base_url("my.victim") == "https://s3.amazonaws.com/my.victim"


def test_public_listing_detected():
    http = _FakeHttp({"victim.s3.amazonaws.com/": _Resp(200, _LIST_XML)})
    findings = S3BucketScanner(http_engine=http).run(S3BucketTarget(bucket="victim"))
    cats = {f.category for f in findings}
    assert "s3-bucket-public-listing" in cats
    # Read-only: the scanner must never send a mutating method.
    assert all(method == "GET" for method, _ in http.calls)


def test_public_object_read_detected():
    http = _FakeHttp({
        "victim.s3.amazonaws.com/secret.txt": _Resp(200, "topsecret"),
    })
    findings = S3BucketScanner(http_engine=http).run(
        S3BucketTarget(bucket="victim", sample_object_key="secret.txt")
    )
    assert any(f.category == "s3-bucket-public-object" for f in findings)


def test_public_acl_detected_but_write_not_reported_without_confirm():
    http = _FakeHttp({"?acl": _Resp(200, _ACL_WRITABLE)})
    findings = S3BucketScanner(http_engine=http, confirm_writes=False).run(
        S3BucketTarget(bucket="victim")
    )
    cats = {f.category for f in findings}
    assert "s3-bucket-public-acl" in cats
    # Write exposure must NOT be concluded unless explicitly confirmed.
    assert "s3-bucket-public-writable" not in cats


def test_writable_inferred_from_acl_only_with_confirm():
    http = _FakeHttp({"?acl": _Resp(200, _ACL_WRITABLE)})
    findings = S3BucketScanner(http_engine=http, confirm_writes=True).run(
        S3BucketTarget(bucket="victim")
    )
    writable = [f for f in findings if f.category == "s3-bucket-public-writable"]
    assert writable
    ev = writable[0].evidence
    assert ev["check"] == "write_permission_inferred_from_acl"
    assert ev["inferred_write_grant"]  # non-empty list of granted perms
    # Still only GETs - the "writable" conclusion came from reading the ACL.
    assert all(method == "GET" for method, _ in http.calls)


def test_read_only_acl_is_not_writable_even_with_confirm():
    http = _FakeHttp({"?acl": _Resp(200, _ACL_READ_ONLY)})
    findings = S3BucketScanner(http_engine=http, confirm_writes=True).run(
        S3BucketTarget(bucket="victim")
    )
    cats = {f.category for f in findings}
    assert "s3-bucket-public-acl" in cats
    assert "s3-bucket-public-writable" not in cats


def test_private_bucket_yields_nothing():
    http = _FakeHttp({
        "victim": _Resp(403, "<Error><Code>AccessDenied</Code></Error>"),
    })
    findings = S3BucketScanner(http_engine=http).run(S3BucketTarget(bucket="victim"))
    assert findings == []


# ---------------------------------------------------------------------------
# Phase 5: OPTIONAL lab-mode ACTIVE write-confirmation probe.
#
# The probe may send a real PUT/DELETE, so it is triple-gated: env var
# WILY_ALLOW_S3_WRITE=true, the --s3-lab-write flag (lab_write=True), AND the
# bucket inside an owned/lab bucket scope. These tests use a scripted fake
# engine (no real S3) and assert the probe fires ONLY when all three hold.
# ---------------------------------------------------------------------------

_ENV_VAR = "WILY_ALLOW_S3_WRITE"


class _WriteFakeHttp:
    """Records every (method, url, body) and answers PUT/DELETE explicitly.

    Read checks (GET) return a benign 404 so they contribute no findings,
    isolating the active-write path under test.
    """

    def __init__(self, put=None, delete=None):
        self.calls = []
        self._put = put or _Resp(200)
        self._delete = delete or _Resp(204)

    def request(self, method, url, headers=None, body=None):
        self.calls.append((method, url, body))
        if method == "PUT":
            return self._put
        if method == "DELETE":
            return self._delete
        return _Resp(404, "<Error><Code>NoSuchKey</Code></Error>")

    @property
    def methods(self):
        return [m for m, _u, _b in self.calls]


def _owned_scope():
    """A scope that both names the domain target and declares 'victim' an
    owned/lab bucket (so gate 3 can pass)."""
    return ScopeManager("example.com", s3_buckets=("victim",))


def test_lab_write_skipped_when_env_var_unset(monkeypatch):
    monkeypatch.delenv(_ENV_VAR, raising=False)
    http = _WriteFakeHttp()
    findings = S3BucketScanner(
        scope_manager=_owned_scope(), http_engine=http, lab_write=True
    ).run(S3BucketTarget(bucket="victim"))
    # Gate 1 (env var) fails: no mutating request, no active finding.
    assert "PUT" not in http.methods and "DELETE" not in http.methods
    assert not any(f.category == "s3-bucket-public-writable" for f in findings)


def test_lab_write_skipped_when_flag_off(monkeypatch):
    monkeypatch.setenv(_ENV_VAR, "true")
    http = _WriteFakeHttp()
    # lab_write defaults False: gate 2 fails even though env + scope are fine.
    findings = S3BucketScanner(
        scope_manager=_owned_scope(), http_engine=http
    ).run(S3BucketTarget(bucket="victim"))
    assert "PUT" not in http.methods and "DELETE" not in http.methods
    assert not any(f.category == "s3-bucket-public-writable" for f in findings)


def test_lab_write_fires_even_when_scope_not_owned(monkeypatch):
    """The active write probe only has two gates now (env var + --s3-lab-write):
    no bucket-scope check. A knowingly removed safety check - the probe fires
    on ANY bucket the scanner reaches once both flags are set, not only one
    declared owned/lab via --scope-bucket."""
    monkeypatch.setenv(_ENV_VAR, "true")
    http = _WriteFakeHttp(put=_Resp(200), delete=_Resp(204))
    scope = ScopeManager("example.com")
    assert not scope.has_bucket_scope
    findings = S3BucketScanner(
        scope_manager=scope, http_engine=http, lab_write=True
    ).run(S3BucketTarget(bucket="victim"))
    assert "PUT" in http.methods and "DELETE" in http.methods
    assert any(f.category == "s3-bucket-public-writable" for f in findings)


def test_lab_write_fires_with_both_gates(monkeypatch):
    monkeypatch.setenv(_ENV_VAR, "true")
    http = _WriteFakeHttp(put=_Resp(200), delete=_Resp(204))
    findings = S3BucketScanner(
        scope_manager=_owned_scope(), http_engine=http, lab_write=True
    ).run(S3BucketTarget(bucket="victim"))

    # A (faked) PUT then DELETE actually happened, in that order.
    assert "PUT" in http.methods
    assert "DELETE" in http.methods
    assert http.methods.index("PUT") < http.methods.index("DELETE")
    # Both target the unmistakable marker key, and the DELETE cleans up the
    # exact object that was PUT.
    put_url = next(u for m, u, _b in http.calls if m == "PUT")
    del_url = next(u for m, u, _b in http.calls if m == "DELETE")
    assert "/wily-check-" in put_url and put_url.endswith(".txt")
    assert del_url == put_url

    writable = [f for f in findings if f.category == "s3-bucket-public-writable"]
    assert len(writable) == 1
    ev = writable[0].evidence
    assert ev["check"] == "write_permission_confirmed_active_lab_put"
    assert ev["active_probe"] is True
    assert ev["cleanup_ok"] is True
    assert "cleanup_failed" not in ev
    assert writable[0].severity == "critical"


def test_lab_write_not_reported_when_put_rejected(monkeypatch):
    monkeypatch.setenv(_ENV_VAR, "true")
    # A 403 PUT means the bucket is NOT writable: nothing is created and no
    # finding is emitted, but cleanup is still attempted (harmless no-op).
    http = _WriteFakeHttp(put=_Resp(403), delete=_Resp(404))
    findings = S3BucketScanner(
        scope_manager=_owned_scope(), http_engine=http, lab_write=True
    ).run(S3BucketTarget(bucket="victim"))
    assert "PUT" in http.methods  # the probe tried
    assert not any(f.category == "s3-bucket-public-writable" for f in findings)


def test_lab_write_surfaces_failed_cleanup(monkeypatch):
    monkeypatch.setenv(_ENV_VAR, "true")
    # PUT succeeds (bucket writable) but the cleanup DELETE is refused: the
    # finding must warn that the marker object may still exist.
    http = _WriteFakeHttp(put=_Resp(200), delete=_Resp(403))
    findings = S3BucketScanner(
        scope_manager=_owned_scope(), http_engine=http, lab_write=True
    ).run(S3BucketTarget(bucket="victim"))
    writable = [f for f in findings if f.category == "s3-bucket-public-writable"]
    assert len(writable) == 1
    ev = writable[0].evidence
    assert ev["cleanup_ok"] is False
    assert ev["cleanup_failed"] is True
    assert "may still exist" in ev["cleanup_warning"]
    assert "cleanup of the marker object FAILED" in writable[0].remediation


@pytest.mark.parametrize("env_value", ["false", "0", "no", "", "  "])
def test_lab_write_env_var_must_be_truthy(monkeypatch, env_value):
    monkeypatch.setenv(_ENV_VAR, env_value)
    http = _WriteFakeHttp()
    S3BucketScanner(
        scope_manager=_owned_scope(), http_engine=http, lab_write=True
    ).run(S3BucketTarget(bucket="victim"))
    # A non-truthy env value is treated as "off": no mutating request.
    assert "PUT" not in http.methods and "DELETE" not in http.methods


def test_read_only_default_sends_no_put_or_delete(monkeypatch):
    # Belt-and-braces: even with env var set, the DEFAULT scanner (no
    # lab_write) never sends a mutating request.
    monkeypatch.setenv(_ENV_VAR, "true")
    http = _WriteFakeHttp()
    S3BucketScanner(scope_manager=_owned_scope(), http_engine=http).run(
        S3BucketTarget(bucket="victim")
    )
    assert all(m == "GET" for m in http.methods)
