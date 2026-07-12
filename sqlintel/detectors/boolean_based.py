"""Boolean-based blind detection.

Idea: a TRUE condition should make the page look like the baseline, while a FALSE
condition should make it visibly differ. We compare response similarity to separate
the two. This catches injections that emit no error and no timing signal.
"""

from __future__ import annotations

from difflib import SequenceMatcher
from typing import Optional

from ..core.http_client import Response
from ..core.target import Finding, InjectionPoint, Request
from ..payloads.data import BOOLEAN_PAIRS
from .base import BaseDetector

# Similarity thresholds (0..1). Tuned conservatively to limit false positives.
TRUE_SIMILAR = 0.95   # TRUE response should closely match baseline
FALSE_DIVERGE = 0.90  # FALSE response should drop clearly below TRUE's similarity


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


class BooleanBasedDetector(BaseDetector):
    name = "boolean-based"

    def test(self, req: Request, point: InjectionPoint) -> Optional[Finding]:
        base_text = self.baseline.text

        for true_payload, false_payload in BOOLEAN_PAIRS:
            true_resp: Response = self.client.send(
                req, mutation={point.param: self._mutate_value(point, true_payload)}
            )
            if not true_resp.ok:  # inconclusive probe, skip this pair
                continue
            # Only worth testing FALSE if TRUE looks like the baseline.
            true_sim = _similarity(base_text, true_resp.text)
            if true_sim < TRUE_SIMILAR:
                continue

            false_resp: Response = self.client.send(
                req, mutation={point.param: self._mutate_value(point, false_payload)}
            )
            if not false_resp.ok:
                continue
            false_sim = _similarity(base_text, false_resp.text)

            # Vulnerable: TRUE ≈ baseline, FALSE clearly diverges from it.
            if false_sim < FALSE_DIVERGE and (true_sim - false_sim) > 0.05:
                margin = true_sim - false_sim
                return Finding(
                    injection_point=point,
                    technique=self.name,
                    payload=f"TRUE={true_payload!r} / FALSE={false_payload!r}",
                    evidence=(
                        f"baseline~TRUE similarity={true_sim:.3f}, "
                        f"baseline~FALSE similarity={false_sim:.3f}"
                    ),
                    # Confidence scales with how cleanly TRUE/FALSE separate.
                    confidence=min(0.6 + margin, 0.95),
                )
        return None
