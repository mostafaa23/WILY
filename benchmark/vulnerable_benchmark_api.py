"""A local-only benchmark target with a KNOWN ground truth.

The point of this app is to produce, in one scan, a mix of:

  * a genuine authorization bug (a real missing authorizer the scanner
    SHOULD report), and
  * endpoints that look like data leaks to a naive scanner but are not -
    the exact pattern that inflates a DAST tool's false-positive rate.

The false-positive source here is a realistic and well-documented one: a
catch-all route (an SPA/default-integration fallback) that answers 200 with
the same generic body for *every* path that was not explicitly defined. A
scanner that treats "200 with no auth header" as a leak will flag every
probed-but-undefined path as a missing authorizer, even though they all
resolve to one generic page and leak nothing.

Ground truth is declared in GROUND_TRUTH below so the benchmark can score
each finding as a true or false positive without guessing.
"""

from __future__ import annotations

from flask import Flask, jsonify, request

app = Flask(__name__)


# --- The ONE genuine vulnerability -------------------------------------
# GET requires auth (401 without a token); DELETE forgot its authorizer and
# returns real order data to anyone. This is a true missing_authorizer /
# method_inconsistency finding - the scanner is CORRECT to report it.
@app.route("/orders/4215", methods=["GET"])
def get_order():
    if request.headers.get("Authorization") != "Bearer valid-token":
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"order_id": 4215, "amount": 500, "customer": "Jane Roe"}), 200


@app.route("/orders/4215", methods=["DELETE"])
def delete_order():
    # The intended bug: no auth check at all on DELETE.
    return jsonify({"order_id": 4215, "status": "deleted", "customer": "Jane Roe"}), 200


# --- A correctly protected resource (true negative) --------------------
# Every method needs auth. The scanner should report NOTHING here; if it
# does, that is also a false positive.
@app.route("/account/profile", methods=["GET", "POST", "PUT", "DELETE"])
def account_profile():
    if request.headers.get("Authorization") != "Bearer valid-token":
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"user": "jane", "email": "jane@example.com"}), 200


# --- The false-positive source: a generic catch-all -------------------
# Any path not matched above falls here and returns 200 with the SAME
# generic body. To a scanner, each distinct probed path looks like a
# separate unauthenticated 200 "leak"; in reality they are all one page
# that carries no resource data at all.
_CATCH_ALL_BODY = {
    "message": "Welcome to the Example API",
    "status": "ok",
    "docs": "https://example.com/docs",
}


@app.route("/", defaults={"_path": ""})
@app.route("/<path:_path>")
def catch_all(_path: str):
    return jsonify(_CATCH_ALL_BODY), 200


# A path that is guaranteed never to be a real resource - used as the
# differential soft-404 baseline. It resolves to the same catch-all body,
# which is the whole point: real missing resources here look identical to
# the "leaks" above, so a body-similarity comparison can separate them.
SOFT_404_PATH = "/__wily_nonexistent_probe_8f31__"


# --- Ground truth -------------------------------------------------------
# Maps each path the benchmark will scan to whether a finding on it is a
# TRUE positive (a real bug) or a FALSE positive (the catch-all / a
# correctly protected resource). The benchmark scores findings against this
# so no number is a guess.
GROUND_TRUTH: dict[str, bool] = {
    # path: is a finding here a real vulnerability?
    "/orders/4215": True,          # genuine missing authorizer on DELETE
    "/account/profile": False,     # correctly protected - any finding is an FP
    "/api/reports/annual": False,  # catch-all - not a real resource
    "/api/legacy/v1/widgets": False,
    "/dashboard/metrics": False,
    "/internal/config": False,
    "/billing/invoices/2024": False,
}


if __name__ == "__main__":  # pragma: no cover - manual smoke run only
    app.run(port=5099)
