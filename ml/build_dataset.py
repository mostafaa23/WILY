"""Bootstrap a LABELED triage dataset from known-ground-truth targets.

Wily's triage layer is heuristic-only because a trained model needs labeled
findings, and in the field those only come from many analysts marking results
over a long time. This script sidesteps that chicken-and-egg problem by
generating the labels from targets whose ground truth we already know, entirely
offline and reproducibly:

  1. An embedded set of secret-exposure sources (real-shaped leaked credentials
     vs. documentation/placeholder look-alikes) scanned with SecretScanScanner.
     No server, no network - always available, even in a fresh clone.
  2. The benchmark app (benchmark/vulnerable_benchmark_api.py), which declares a
     GROUND_TRUTH, scanned with AuthzBypassScanner. Committed, so always present.
  3. The demo authz app (demo/vulnerable_authz_api.py) when present - it also
     declares a GROUND_TRUTH. The demo/ tree is local-only, so this is optional
     augmentation that simply adds more labeled rows when you have it.
  4. Optionally, any analyst decisions from a FeedbackStore JSONL (--feedback),
     which OVERRIDE the ground-truth label for findings they match.

Each finding is auto-labeled VALID / FALSE_POSITIVE from the declared ground
truth, turned into the fixed numeric feature vector (wily.risk.ml.features -
no label leakage), and written as one JSONL row.

    python ml/build_dataset.py                 # -> ml/data/triage_dataset.jsonl
    python ml/build_dataset.py --out mine.jsonl --feedback feedback.jsonl

Pointing it at EXTERNAL vulnerable apps (optional, not required):
    Juice Shop / VAmPI / crAPI and friends can be folded in the same way - run
    one locally, enumerate the endpoints whose ground truth you know, and add an
    `HttpAuthzTarget(name=..., app_or_base_url=..., ground_truth={path: bool})`.
    Nothing here reaches the network on its own; you stand the app up yourself.
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import requests

_ML_DIR = Path(__file__).resolve().parent
_REPO = _ML_DIR.parent
sys.path.insert(0, str(_REPO / "src"))

from wily.core.scope_manager import ScopeManager  # noqa: E402
from wily.risk.ml.dataset import (  # noqa: E402
    dataset_summary,
    label_findings,
    make_path_labeler,
    write_dataset,
)
from wily.risk.ml.feedback import FeedbackStore  # noqa: E402
from wily.scanners.authz_bypass import AuthzBypassScanner, AuthzBypassTarget  # noqa: E402
from wily.scanners.secret_scan import (  # noqa: E402
    SecretScanScanner,
    SecretScanTarget,
    SecretSource,
)

_DEFAULT_OUT = _ML_DIR / "data" / "triage_dataset.jsonl"
_HOST = "127.0.0.1"
# A path guaranteed never to be a real resource, used as the differential
# soft-404 baseline so the similarity feature is populated on every finding.
_SOFT_404_PATH = "/__wily_ml_nonexistent_probe_0x7f__"


# ---------------------------------------------------------------------------
# 1. Offline secret-exposure sources (no server).
# ---------------------------------------------------------------------------
# VALID: text blobs that leak a real-shaped, high-confidence credential - the
# kind an analyst would act on. FALSE_POSITIVE: documentation / template / test
# snippets that merely LOOK secret to a regex (placeholder values, example
# bearer tokens) - a well-known secret-scanner false-positive class. The values
# below are synthetic and inert (never used against anything); they exist only
# so the scanner has something shaped like a secret to detect and label.
_SECRET_VALID_SOURCES = [
    SecretSource(
        label="app.min.js",
        location="https://assets.example.com/app.min.js",
        content='const AWS_KEY="AKIA3MLWXZ7QRSTUVWX2";const r=fetch("/api");',
    ),
    SecretSource(
        label="config.leaked.json",
        location="https://cdn.example.com/config.leaked.json",
        content='{"github_token": "ghp_AbCdEf0123456789AbCdEf0123456789AbCd"}',
    ),
    SecretSource(
        label="deploy.log",
        location="https://ci.example.com/deploy.log",
        content="google maps key AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R",
    ),
    SecretSource(
        label="backup.env",
        location="https://files.example.com/backup.env",
        content=(
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Q\n"
            "-----END RSA PRIVATE KEY-----\n"
        ),
    ),
]
_SECRET_FP_SOURCES = [
    SecretSource(
        label="README.md",
        location="https://docs.example.com/README.md",
        content="Call the API with:  curl -H 'Authorization: Bearer example-token-abc123456789'",
    ),
    SecretSource(
        label="config.template.yaml",
        location="https://docs.example.com/config.template.yaml",
        content='api_key: "REPLACE_WITH_YOUR_API_KEY_HERE"',
    ),
    SecretSource(
        label="sdk-quickstart.md",
        location="https://docs.example.com/sdk-quickstart.md",
        content="access_token=EXAMPLE0000PLACEHOLDER0000TOKEN0000VALUE",
    ),
    SecretSource(
        label="integration_test.py",
        location="https://docs.example.com/integration_test.py",
        content='client_secret = "dummy000secret000for000unit000tests"',
    ),
]


def collect_secret_rows() -> list[dict]:
    """Scan the embedded secret sources and label each finding by which source
    bucket it came from (real-shaped leak -> VALID, placeholder/example -> FP)."""
    scanner = SecretScanScanner()

    def _scan(sources: list[SecretSource]) -> list:
        return scanner.run(SecretScanTarget(sources=sources))

    valid_findings = _scan(_SECRET_VALID_SOURCES)
    fp_findings = _scan(_SECRET_FP_SOURCES)

    rows: list[dict] = []
    rows += label_findings(valid_findings, lambda f: "VALID", "secret-sources")
    rows += label_findings(fp_findings, lambda f: "FALSE_POSITIVE", "secret-sources")
    return rows


# ---------------------------------------------------------------------------
# 2 & 3. HTTP authz targets (benchmark app + optional demo app).
# ---------------------------------------------------------------------------
@dataclass
class HttpAuthzTarget:
    name: str
    app: object            # a Flask app to serve locally
    port: int
    ground_truth: dict[str, bool]


def _start_app(app, port: int) -> None:
    thread = threading.Thread(
        target=lambda: app.run(host=_HOST, port=port, use_reloader=False),
        daemon=True,
    )
    thread.start()
    # Wait until it actually answers, rather than a blind sleep.
    base = f"http://{_HOST}:{port}"
    for _ in range(40):
        try:
            requests.get(base + _SOFT_404_PATH, timeout=0.5)
            return
        except requests.RequestException:
            time.sleep(0.25)
    raise RuntimeError(f"local app '{base}' did not come up")


def collect_authz_rows(target: HttpAuthzTarget, feedback: dict[str, str] | None) -> list[dict]:
    """Serve the app locally, scan every ground-truth path with the authz
    scanner, and label each finding against the declared ground truth.

    The soft-404 probe is enabled so the differential-similarity feature is
    populated, but the scanner's filter threshold is set ABOVE 1.0 so nothing is
    dropped - we want the catch-all false positives to appear as labeled rows the
    model can learn from, not to be silently filtered out here.
    """
    _start_app(target.app, target.port)
    base = f"http://{_HOST}:{target.port}"
    scope = ScopeManager(_HOST, allow_local_targets=True)
    scanner = AuthzBypassScanner(scope_manager=scope, confirm_destructive=True)
    labeler = make_path_labeler(target.ground_truth)

    findings: list = []
    for path in target.ground_truth:
        at = AuthzBypassTarget(
            url=f"{base}{path}",
            methods_to_test=["GET"],
            include_destructive_methods=True,
            soft_404_probe_url=f"{base}{_SOFT_404_PATH}",
            soft_404_similarity_threshold=1.01,  # record similarity, filter nothing
        )
        findings += scanner.run(at)
    return label_findings(findings, labeler, target.name, feedback=feedback)


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _benchmark_target() -> HttpAuthzTarget | None:
    path = _REPO / "benchmark" / "vulnerable_benchmark_api.py"
    if not path.exists():
        return None
    mod = _load_module(path, "_wily_bench_app")
    return HttpAuthzTarget("benchmark-app", mod.app, 5099, dict(mod.GROUND_TRUTH))


def _demo_authz_target() -> HttpAuthzTarget | None:
    path = _REPO / "demo" / "vulnerable_authz_api.py"
    if not path.exists():
        return None
    mod = _load_module(path, "_wily_demo_authz_app")
    ground_truth = getattr(mod, "GROUND_TRUTH", None)
    if not ground_truth:
        return None
    return HttpAuthzTarget("demo-authz-app", mod.app, 5098, dict(ground_truth))


def build_rows(feedback_path: str | None) -> list[dict]:
    feedback = None
    if feedback_path:
        feedback = {
            d.hash_key: ("VALID" if d.verdict == "valid" else "FALSE_POSITIVE")
            for d in FeedbackStore(feedback_path).all_decisions()
        }

    rows: list[dict] = []
    rows += collect_secret_rows()

    for factory in (_benchmark_target, _demo_authz_target):
        target = factory()
        if target is None:
            print(f"  [skip] {factory.__name__}: target not available")
            continue
        try:
            target_rows = collect_authz_rows(target, feedback)
            rows += target_rows
            print(f"  [ok]   {target.name}: {len(target_rows)} labeled rows")
        except Exception as exc:  # pragma: no cover - environment-dependent
            print(f"  [warn] {target.name}: scan failed ({exc}); skipped")
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(_DEFAULT_OUT), help="output JSONL path")
    parser.add_argument(
        "--feedback",
        default=None,
        help="optional FeedbackStore JSONL whose analyst verdicts override labels",
    )
    args = parser.parse_args()

    print("Building bootstrapped triage dataset (offline)...")
    rows = build_rows(args.feedback)
    out = write_dataset(rows, args.out)

    summary = dataset_summary(rows)
    print("\nDataset summary")
    print("  total rows      :", summary["total"])
    print("  VALID           :", summary["valid"])
    print("  FALSE_POSITIVE  :", summary["false_positive"])
    print("  by source       :", summary["by_source"])
    print("  by category     :", summary["by_category"])
    print(f"\n  written to {Path(out).resolve()}")
    if summary["valid"] < 2 or summary["false_positive"] < 2:
        print(
            "\n  [!] too few of one class to train/evaluate; add the demo apps or "
            "an external target (see this script's docstring)."
        )


if __name__ == "__main__":
    main()
