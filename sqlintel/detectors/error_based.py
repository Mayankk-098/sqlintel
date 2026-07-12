"""Error-based detection: inject a syntax-breaking character and look for a DB error
that was NOT present in the baseline response."""

from __future__ import annotations

from typing import Optional

from ..core.target import Finding, InjectionPoint, Request
from ..payloads.data import ERROR_PROBES, match_dbms_error
from .base import BaseDetector


class ErrorBasedDetector(BaseDetector):
    name = "error-based"

    def test(self, req: Request, point: InjectionPoint) -> Optional[Finding]:
        # If the baseline already shows a DB error, error-based signal is unreliable.
        base_dbms, _ = match_dbms_error(self.baseline.text)

        for probe in ERROR_PROBES:
            mutated = self._mutate_value(point, probe)
            resp = self.client.send(req, mutation={point.param: mutated})
            if not resp.ok:  # network error on this probe — inconclusive, try the next
                continue
            dbms, snippet = match_dbms_error(resp.text)
            if dbms and not base_dbms:
                return Finding(
                    injection_point=point,
                    technique=self.name,
                    dbms=dbms,
                    payload=probe,
                    evidence=snippet,
                    confidence=0.9,  # error signatures are strong but can be reflected
                )
        return None
