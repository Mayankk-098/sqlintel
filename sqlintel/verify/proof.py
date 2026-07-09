"""Proof-based verification.

A finding from the detection engine is *suspected*. Before we call it PROVEN, we
re-confirm it a second, independent way — using different payloads than detection
used. This is the open-source, $0 version of commercial "proof-based scanning":
we don't just pattern-match once, we reproduce the behavior deterministically.

Rules:
  * boolean-based: re-run an ORTHOGONAL true/false pair; the same true~baseline /
    false-diverges pattern must hold again.
  * error-based: an unbalanced quote must raise a DB error AND a balanced (doubled)
    quote must NOT — the error has to toggle with quote balance.
  * time-based: the engine already double-confirms with a 0s control, so it arrives
    pre-proven; we leave it as-is.

Verification only ever RAISES confidence / sets `proven=True`. It never deletes a
finding — deciding "vulnerable or not" stays with the deterministic detectors.
"""

from __future__ import annotations

from difflib import SequenceMatcher

from ..core.http_client import HttpClient, Response
from ..core.target import Finding, Request
from ..payloads.data import (
    PROOF_BOOLEAN_PAIRS,
    PROOF_ERROR_FIX,
    PROOF_ERROR_BREAK,
    match_dbms_error,
)

_TRUE_SIMILAR = 0.95
_FALSE_DIVERGE = 0.90


def _sim(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


class ProofVerifier:
    def __init__(self, client: HttpClient, baseline: Response) -> None:
        self.client = client
        self.baseline = baseline

    def verify(self, req: Request, finding: Finding) -> Finding:
        if finding.technique == "boolean-based":
            self._verify_boolean(req, finding)
        elif finding.technique == "error-based":
            self._verify_error(req, finding)
        # time-based arrives pre-proven from the detector's control re-check.
        return finding

    # -- helpers ---------------------------------------------------------------
    def _mutate(self, finding: Finding, payload: str) -> str:
        return f"{finding.injection_point.value}{payload}"

    def _verify_boolean(self, req: Request, finding: Finding) -> None:
        param = finding.injection_point.param
        for true_p, false_p in PROOF_BOOLEAN_PAIRS:
            true_resp = self.client.send(req, mutation={param: self._mutate(finding, true_p)})
            false_resp = self.client.send(req, mutation={param: self._mutate(finding, false_p)})
            true_sim = _sim(self.baseline.text, true_resp.text)
            false_sim = _sim(self.baseline.text, false_resp.text)
            if true_sim >= _TRUE_SIMILAR and false_sim < _FALSE_DIVERGE:
                finding.proven = True
                finding.confidence = min(finding.confidence + 0.1, 0.99)
                finding.evidence += (
                    f" | PROVEN via orthogonal pair {true_p!r}/{false_p!r} "
                    f"(true~{true_sim:.3f}, false~{false_sim:.3f})"
                )
                return

    def _verify_error(self, req: Request, finding: Finding) -> None:
        param = finding.injection_point.param
        broke = self.client.send(req, mutation={param: self._mutate(finding, PROOF_ERROR_BREAK)})
        fixed = self.client.send(req, mutation={param: self._mutate(finding, PROOF_ERROR_FIX)})
        dbms_broke, snippet = match_dbms_error(broke.text)
        dbms_fixed, _ = match_dbms_error(fixed.text)
        # Error appears with unbalanced quote, disappears when balanced → proven.
        if dbms_broke and not dbms_fixed:
            finding.proven = True
            finding.dbms = finding.dbms or dbms_broke
            finding.confidence = min(finding.confidence + 0.09, 0.99)
            finding.evidence += (
                f" | PROVEN: error toggles with quote balance "
                f"(' -> error, '' -> clean); {snippet}"
            )
