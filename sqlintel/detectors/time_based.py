"""Time-based blind detection.

Idea: inject a payload that tells the DB to sleep N seconds. If the response time
jumps by ~N (and a control request does not), the parameter is injectable. We
re-confirm before reporting to defend against a slow/jittery network — a cheap,
built-in first step toward proof-based verification.
"""

from __future__ import annotations

from typing import Optional

from ..core.target import Finding, InjectionPoint, Request
from ..payloads.data import all_time_payloads
from .base import BaseDetector


class TimeBasedDetector(BaseDetector):
    name = "time-based"

    def __init__(self, client, baseline, delay: int = 5) -> None:
        super().__init__(client, baseline)
        self.delay = delay

    def test(self, req: Request, point: InjectionPoint) -> Optional[Finding]:
        # Threshold: response must take at least this long to count as "slept".
        # Baseline latency + most of the requested delay.
        threshold = self.baseline.elapsed + (self.delay * 0.8)

        for dbms, payload in all_time_payloads(self.delay):
            resp = self.client.send(
                req, mutation={point.param: self._mutate_value(point, payload)}
            )
            if not resp.ok or resp.elapsed < threshold:
                continue

            # Re-confirm with a 0-second control: it should return fast.
            control_payload = payload.replace(f"{self.delay}", "0")
            control = self.client.send(
                req, mutation={point.param: self._mutate_value(point, control_payload)}
            )
            # A failed control is inconclusive — don't let a network error masquerade as
            # a fast control and thereby "confirm" the delay.
            if control.ok and control.elapsed < threshold:
                return Finding(
                    injection_point=point,
                    technique=self.name,
                    dbms=dbms,
                    payload=payload,
                    evidence=(
                        f"delayed={resp.elapsed:.2f}s vs control={control.elapsed:.2f}s "
                        f"(threshold={threshold:.2f}s)"
                    ),
                    confidence=0.85,
                    # Timing confirmed twice → treat as proven for MVP purposes.
                    proven=True,
                )
        return None
