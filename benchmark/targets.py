"""Labeled benchmark targets — the ground truth every tool is scored against.

Each :class:`Target` carries a known ``vulnerable`` label. The mock suite is the
*primary* metric because it is fully reproducible (no external services, deterministic
responses) and — crucially — includes SAFE endpoints as true negatives so we can measure
the false-positive rate, not just recall. The DVWA set documents a realistic, if
non-reproducible-in-CI, second data point.

`body_kind` tells the harness how each tool should send the parameter:
  * "query" -> URL query string   (?id=1)
  * "form"  -> urlencoded body     (id=1)
  * "json"  -> JSON API body       ({"id": 1})  <- SQLintel's differentiator
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class Target:
    id: str                 # stable short name, used in result tables
    method: str             # "GET" | "POST"
    path: str               # path (+ query for GET), joined onto the base URL
    param: str              # the parameter under test
    body_kind: str          # "query" | "form" | "json"
    data: Optional[str]     # raw body for form/json targets (None for query targets)
    vulnerable: bool        # ground-truth label
    note: str = ""


# --- Mock suite (primary, reproducible) -------------------------------------------------
# Served by tests/mock_vuln_server.py. 2 vulnerable + 2 safe = enough to populate every
# cell of the confusion matrix (TP/FP/TN/FN) for each tool.
MOCK_TARGETS: List[Target] = [
    Target(
        id="mock-item-query",
        method="GET",
        path="/item?id=1",
        param="id",
        body_kind="query",
        data=None,
        vulnerable=True,
        note="Classic error/boolean/time sink on a query param.",
    ),
    Target(
        id="mock-api-json",
        method="POST",
        path="/api/item",
        param="id",
        body_kind="json",
        data='{"id": 1}',
        vulnerable=True,
        note="JSON API body sink — the case SQLintel targets directly via --json-body.",
    ),
    Target(
        id="mock-safe-query",
        method="GET",
        path="/safe/item?id=1",
        param="id",
        body_kind="query",
        data=None,
        vulnerable=False,
        note="True negative: input ignored, constant reply. Any 'finding' is a FP.",
    ),
    Target(
        id="mock-safe-json",
        method="POST",
        path="/safe/api/item",
        param="id",
        body_kind="json",
        data='{"id": 1}',
        vulnerable=False,
        note="True negative on a JSON endpoint.",
    ),
]


# --- DVWA suite (documented, real-world second data point) ------------------------------
# Requires the bundled docker-compose DVWA at security=low and an authenticated session.
# See benchmark/README.md for the auth path (PHPSESSID + security=low cookie). These are
# GET query sinks on DVWA's SQLi modules; there is no built-in "guaranteed safe" endpoint,
# so FP-rate on this set is only meaningful once you add your own labeled safe pages.
DVWA_TARGETS: List[Target] = [
    Target(
        id="dvwa-sqli",
        method="GET",
        path="/vulnerabilities/sqli/?id=1&Submit=Submit",
        param="id",
        body_kind="query",
        data=None,
        vulnerable=True,
        note="DVWA classic SQLi module (security=low).",
    ),
    Target(
        id="dvwa-sqli-blind",
        method="GET",
        path="/vulnerabilities/sqli_blind/?id=1&Submit=Submit",
        param="id",
        body_kind="query",
        data=None,
        vulnerable=True,
        note="DVWA blind (boolean/time) SQLi module (security=low).",
    ),
]


TARGET_SETS: Dict[str, List[Target]] = {
    "mock": MOCK_TARGETS,
    "dvwa": DVWA_TARGETS,
}
