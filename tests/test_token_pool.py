"""File-based token/session pool: parsing, liveness filtering, and the
BOLA fill contract (explicit --identity wins, pool tops up to two).

All offline: a fake, scripted HTTP engine returns canned status codes;
nothing is fetched over the network.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from wily.recon.token_pool import (
    PooledIdentity,
    parse_token_pool,
    select_live_identities,
)
from wily.scanners.bola import Identity

# A real, structurally valid JWT (header {"alg":"HS256","typ":"JWT"},
# payload {"sub":"1234","name":"Alice"}) - decodes to JSON on both segments.
VALID_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0IiwibmFtZSI6IkFsaWNlIn0"
    ".c2lnbmF0dXJlX2hlcmU"
)
# A second valid JWT (payload {"sub":"9"}), so two identities differ.
VALID_JWT_2 = (
    "eyJhbGciOiJIUzI1NiJ9"
    ".eyJzdWIiOiI5In0"
    ".c2ln"
)


@dataclass
class _Resp:
    status_code: int = 200
    headers: dict = field(default_factory=dict)
    text: str = ""
    elapsed_ms: float = 1.0
    url: str = ""


class _ScriptedEngine:
    """Returns a status per identity, keyed by the identity's own header value
    so each probe gets the response the test scripted for it. Records every
    (url, headers) it was asked for, so we can assert GET-only and bounded."""

    def __init__(self, status_by_marker: dict[str, int]):
        self._status_by_marker = status_by_marker
        self.calls: list[tuple[str, dict]] = []

    def request(self, method, url, headers=None, body=None):
        assert method == "GET", "liveness must be read-only GET"
        headers = headers or {}
        self.calls.append((url, headers))
        blob = " ".join(headers.values())
        for marker, status in self._status_by_marker.items():
            if marker in blob:
                return _Resp(status_code=status)
        return _Resp(status_code=404)


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------


def test_parse_authorization_header_spec():
    pool = parse_token_pool(f"a = Authorization: Bearer {VALID_JWT}")
    assert len(pool) == 1
    assert pool[0].name == "a"
    assert pool[0].headers == {"Authorization": f"Bearer {VALID_JWT}"}


def test_parse_cookie_header_spec():
    pool = parse_token_pool("web = Cookie: session=abc123")
    assert pool[0].headers == {"Cookie": "session=abc123"}
    # A cookie value is not a JWT, so it is named but withheld in the label.
    assert "abc123" not in pool[0].label
    assert "Cookie" in pool[0].label


def test_parse_bare_jwt_becomes_bearer():
    pool = parse_token_pool(f"a = {VALID_JWT}")
    assert pool[0].headers == {"Authorization": f"Bearer {VALID_JWT}"}


def test_parse_bare_bearer_prefix_jwt():
    pool = parse_token_pool(f"a = Bearer {VALID_JWT}")
    assert pool[0].headers == {"Authorization": f"Bearer {VALID_JWT}"}


def test_parse_skips_non_jwt_bare_value():
    # A dotted non-JWT string must not be mistaken for a credential.
    pool = parse_token_pool("bad = a.b.c")
    assert pool == []


def test_parse_ignores_blank_and_comment_lines():
    text = "\n".join([
        "# a comment",
        "",
        "   ",
        f"a = {VALID_JWT}",
        "# another comment",
        f"b = {VALID_JWT_2}",
    ])
    pool = parse_token_pool(text)
    assert [p.name for p in pool] == ["a", "b"]


def test_parse_skips_lines_without_equals_or_empty_name():
    pool = parse_token_pool("\n".join([
        "no-equals-here",
        f" = {VALID_JWT}",      # empty name
        "a = ",                 # empty value
    ]))
    assert pool == []


def test_parse_duplicate_name_last_wins():
    pool = parse_token_pool("\n".join([
        f"a = {VALID_JWT}",
        "a = X-Api-Key: zzz",
    ]))
    assert len(pool) == 1
    assert pool[0].headers == {"X-Api-Key": "zzz"}


def test_label_never_contains_raw_jwt():
    pool = parse_token_pool(f"a = Authorization: Bearer {VALID_JWT}")
    assert VALID_JWT not in pool[0].label
    assert pool[0].label.startswith("Authorization: Bearer eyJ...")


# --------------------------------------------------------------------------
# Liveness filtering
# --------------------------------------------------------------------------


def _pid(name: str, marker: str) -> PooledIdentity:
    return PooledIdentity(name=name, headers={"Authorization": f"Bearer {marker}"}, label=name)


def test_live_keeps_200_drops_401_403():
    pool = [_pid("alive", "TOK_OK"), _pid("dead1", "TOK_401"), _pid("dead2", "TOK_403")]
    engine = _ScriptedEngine({"TOK_OK": 200, "TOK_401": 401, "TOK_403": 403})
    live = select_live_identities(pool, "https://t.example", engine, want=3)
    assert [i.name for i in live] == ["alive"]
    assert all(isinstance(i, Identity) for i in live)


def test_live_selects_first_two_and_stops_early():
    pool = [
        _pid("a", "TOK_A"), _pid("b", "TOK_B"),
        _pid("c", "TOK_C"), _pid("d", "TOK_D"),
    ]
    engine = _ScriptedEngine({"TOK_A": 200, "TOK_B": 200, "TOK_C": 200, "TOK_D": 200})
    live = select_live_identities(pool, "https://t.example", engine, want=2)
    assert [i.name for i in live] == ["a", "b"]
    # Bounded: stopped after the second live hit, never probed c or d.
    assert len(engine.calls) == 2


def test_live_skips_over_dead_to_find_two():
    pool = [
        _pid("a", "TOK_401"), _pid("b", "TOK_B"),
        _pid("c", "TOK_403"), _pid("d", "TOK_D"),
    ]
    engine = _ScriptedEngine({"TOK_B": 200, "TOK_D": 200})
    live = select_live_identities(pool, "https://t.example", engine, want=2)
    assert [i.name for i in live] == ["b", "d"]


def test_live_swallows_transport_errors():
    class _Boom:
        def request(self, method, url, headers=None, body=None):
            raise RuntimeError("scope refused")

    pool = [_pid("a", "TOK_A")]
    live = select_live_identities(pool, "https://t.example", _Boom(), want=2)
    assert live == []


# --------------------------------------------------------------------------
# BOLA fill contract: explicit identities win, pool tops up to two
# --------------------------------------------------------------------------


def _fill(explicit_names: list[str], pool: list[PooledIdentity], engine) -> list[str]:
    """Mirror scan_all's fill: explicit identities keep their slots; live
    pooled identities (excluding duplicate names) top up to two."""
    identities = [Identity(name=n, headers={"Authorization": f"Bearer {VALID_JWT}"}) for n in explicit_names]
    if len(identities) < 2:
        taken = {i.name for i in identities}
        candidates = [p for p in pool if p.name not in taken]
        identities += select_live_identities(
            candidates, "https://t.example", engine, want=2 - len(identities)
        )
    return [i.name for i in identities]


def test_one_explicit_identity_topped_up_by_one_live_pool_entry():
    pool = [_pid("p1", "TOK_1"), _pid("p2", "TOK_2")]
    engine = _ScriptedEngine({"TOK_1": 200, "TOK_2": 200})
    names = _fill(["explicit"], pool, engine)
    assert names == ["explicit", "p1"]  # explicit kept; only one slot needed


def test_two_explicit_identities_skip_pool_entirely():
    pool = [_pid("p1", "TOK_1")]
    engine = _ScriptedEngine({"TOK_1": 200})
    names = _fill(["a", "b"], pool, engine)
    assert names == ["a", "b"]
    assert engine.calls == []  # pool never probed - explicit already satisfies BOLA


def test_pool_entry_duplicating_explicit_name_is_excluded():
    pool = [_pid("dup", "TOK_DUP"), _pid("fresh", "TOK_FRESH")]
    engine = _ScriptedEngine({"TOK_DUP": 200, "TOK_FRESH": 200})
    names = _fill(["dup"], pool, engine)
    assert names == ["dup", "fresh"]  # the pool's own "dup" is skipped by name


def test_no_live_pool_entries_leaves_too_few_for_bola():
    pool = [_pid("p1", "TOK_401"), _pid("p2", "TOK_403")]
    engine = _ScriptedEngine({"TOK_401": 401, "TOK_403": 403})
    names = _fill([], pool, engine)
    assert names == []  # nothing live -> BOLA would be skipped
