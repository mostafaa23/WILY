"""Phase: cloud resource name generation (recon/cloud_enum.py).

Pure/offline - no network. Mirrors cloud_enum's build_names expansion and the
per-provider name validity rules.
"""

from wily.recon.cloud_enum import (
    aws_signal_reason,
    azure_account_name,
    build_combo_names,
    build_names,
    clean_text,
    detect_aws_signal,
    extract_seeds,
    generate_candidates,
    keyword_from_domain,
    valid_s3_name,
)


def test_clean_text_lowercases_and_strips():
    assert clean_text("Example_Corp!") == "examplecorp"
    assert clean_text("My-App.Site") == "my-app.site"


def test_build_names_emits_bare_keyword_and_six_forms():
    out = build_names(["acme"], ["dev"])
    assert "acme" in out
    # six combined forms with ., - and no separator, both orders
    for expected in ("acmedev", "acme.dev", "acme-dev", "devacme", "dev.acme", "dev-acme"):
        assert expected in out
    # 1 bare + 6 combined = 7, de-duplicated and order-preserved
    assert out[0] == "acme"
    assert len(out) == 7


def test_build_names_dedupes_and_caps_length():
    # a mutation that would push a name past 63 chars is dropped
    long_mut = "x" * 60
    out = build_names(["acme"], [long_mut])
    assert all(len(n) <= 63 for n in out)
    # "acme" itself still present
    assert "acme" in out


def test_generate_candidates_respects_max():
    out = generate_candidates(["acme"], ["dev", "prod", "test"], max_candidates=4)
    assert len(out) == 4
    assert out[0] == "acme"  # keyword-first ordering preserved


def test_build_combo_names_emits_four_layouts_both_separators():
    out = build_combo_names(["acme"], ["assets"], ["dev"])
    expected = {
        "acme-assets-dev", "assets-acme-dev", "acme-dev-assets", "dev-acme-assets",
        "acmeassetsdev", "assetsacmedev", "acmedevassets", "devacmeassets",
    }
    assert set(out) == expected
    # "-" forms of the first layout come first, so a cap keeps them
    assert out[0] == "acme-assets-dev"


def test_build_combo_names_skips_mutation_equal_to_env_and_invalid():
    out = build_combo_names(["acme"], ["dev", "x" * 60], ["dev"])
    assert "acme-dev-dev" not in out
    assert all(valid_s3_name(n) for n in out)
    assert out == []


def test_generate_candidates_combos_off_by_default():
    plain = generate_candidates(["acme"], ["assets"])
    assert not any(n.count("-") == 2 for n in plain)


def test_generate_candidates_combos_appended_after_two_part():
    two_part = generate_candidates(["acme"], ["assets"])
    out = generate_candidates(["acme"], ["assets"], combos=True)
    assert out[: len(two_part)] == two_part
    assert "acme-assets-dev" in out
    assert len(out) == len(set(out))


def test_generate_candidates_cap_applies_to_combos():
    out = generate_candidates(["acme"], ["assets"], combos=True, max_candidates=10)
    assert len(out) == 10


def test_default_lists_fit_default_caps():
    from wily.cli.commands.scan_all import _cloud_enum_cap

    assert len(generate_candidates(["acme"])) <= _cloud_enum_cap(None, False)
    assert _cloud_enum_cap(None, True) == 3000
    assert _cloud_enum_cap(50, True) == 50
    # default scales per keyword so a second keyword is not starved
    assert _cloud_enum_cap(None, False, 2) == 800
    assert len(generate_candidates(["acme", "acmecorp"])) <= _cloud_enum_cap(None, False, 2)


def test_valid_s3_name():
    assert valid_s3_name("my-bucket")
    assert valid_s3_name("a.b.c")
    assert not valid_s3_name("ab")  # too short
    assert not valid_s3_name("UPPER")  # uppercase not allowed
    assert not valid_s3_name("x" * 64)  # too long


def test_azure_account_name_strips_separators_and_validates():
    assert azure_account_name("acme-dev") == "acmedev"
    assert azure_account_name("acme.backups") == "acmebackups"
    # Result must be 3-24 alphanumerics.
    assert azure_account_name("ab") is None
    assert azure_account_name("x" * 25) is None


def test_keyword_from_domain():
    assert keyword_from_domain("api.example.com") == "example"
    assert keyword_from_domain("example.com") == "example"
    assert keyword_from_domain("shop.example.co.uk") == "example"
    assert keyword_from_domain("https://assets.acme-corp.com/path") == "acme-corp"


# --- Phase 3: automatic seed extraction ------------------------------------


def test_extract_seeds_from_domain():
    assert "example" in extract_seeds(domain="api.example.com")


def test_extract_seeds_from_s3_reference_in_body():
    # An existing bucket name in a response body reveals the org token; the
    # mutation/env parts of the label (prod, assets) are dropped as noise.
    body = 'var cfg={url:"https://acme-prod-assets.s3.amazonaws.com/app.js"};'
    seeds = extract_seeds(texts=[body])
    assert "acme" in seeds
    assert "prod" not in seeds
    assert "assets" not in seeds


def test_extract_seeds_from_js_bundle_and_arn():
    # The org token is mined from the ARN resource (globex), not the generic
    # parts (role, deploy).
    js = 'const r="arn:aws:iam::123456789012:role/globex-admin";'
    seeds = extract_seeds(texts=[js])
    assert "globex" in seeds
    # the ARN keyword and the mutation part are dropped as generic
    assert "role" not in seeds
    assert "admin" not in seeds


def test_extract_seeds_from_azure_and_gcs_references():
    text = (
        "https://umbrellastore.blob.core.windows.net/pub "
        "https://initech-data.storage.googleapis.com/x"
    )
    seeds = extract_seeds(texts=[text])
    assert "umbrellastore" in seeds
    assert "initech" in seeds


def test_extract_seeds_from_headers():
    headers = {
        "Server": "AcmeEdge/2.1",          # product token
        "X-Contoso-Trace-Id": "abc123",    # org token from a custom header name
        "X-Environment": "bluewave-eu",    # env token from the value
        "X-Forwarded-For": "10.0.0.1",     # generic header -> no seed
    }
    seeds = extract_seeds(headers=headers)
    assert "acmeedge" in seeds
    assert "contoso" in seeds
    assert "bluewave" in seeds
    assert "forwarded" not in seeds


def test_extract_seeds_from_html_title_and_meta():
    html = (
        "<title>Umbrella Corp Portal</title>"
        '<meta property="og:site_name" content="Umbrella">'
    )
    seeds = extract_seeds(texts=[html])
    assert "umbrella" in seeds
    # generic page/company words are filtered
    assert "portal" not in seeds
    assert "corp" not in seeds


def test_extract_seeds_dedups_preserving_order():
    seeds = extract_seeds(
        domain="acme.com",
        texts=["acme.s3.amazonaws.com acme.s3.amazonaws.com"],
    )
    assert seeds.count("acme") == 1


def test_extract_seeds_caps_at_max():
    body = " ".join(
        f"{name}.s3.amazonaws.com"
        for name in ("alpha", "bravo", "charlie", "delta", "echo", "foxtrot")
    )
    seeds = extract_seeds(texts=[body], max_seeds=3)
    assert len(seeds) == 3


def test_extract_seeds_empty_when_nothing_to_mine():
    assert extract_seeds(domain="", texts=["just some plain prose, no refs"]) == []


# --- Phase 3: AWS-signal auto-trigger --------------------------------------


def test_detect_aws_signal_positive():
    assert detect_aws_signal("see https://foo.s3.amazonaws.com/x")
    assert detect_aws_signal("s3://my-bucket/key")
    assert detect_aws_signal("arn:aws:iam::123456789012:role/Admin")
    assert detect_aws_signal("https://d111.cloudfront.net/app.js")


def test_detect_aws_signal_negative():
    assert detect_aws_signal("nothing cloudy here, just a lambda function word") is None
    assert detect_aws_signal("") is None


def test_aws_signal_reason_from_iam_clue_finding_reuses_phase1():
    # An AWS signal (Phase 1 ARN clue) auto-enables the pass...
    assert aws_signal_reason(findings_categories=["iam-clue-arn"], texts=[])
    assert aws_signal_reason(findings_categories=["s3-bucket-public-read"], texts=[])


def test_aws_signal_reason_from_observed_text():
    assert aws_signal_reason(texts=["ref https://cdn.example.com amazonaws.com here"])


def test_aws_signal_reason_none_without_signal():
    # ...while the absence of any AWS signal does not.
    assert (
        aws_signal_reason(
            findings_categories=["cors-misconfig", "auth-bypass"],
            texts=["plain endpoints https://api.example.com/users"],
        )
        is None
    )
