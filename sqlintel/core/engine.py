"""Scan orchestration: for each injection point, run each detector until one fires.

This is the deterministic core. The ML layer (sqlintel.ml) plugs in here later to
(a) rank injection points before scanning and (b) re-score findings for FP triage —
but it never replaces the detectors' verdict.
"""

from __future__ import annotations

from typing import Callable, List, Optional

from ..detectors import ALL_DETECTORS, TimeBasedDetector
from ..ml.triage import triage_finding
from .http_client import HttpClient
from .target import Finding, Request


class Engine:
    def __init__(
        self,
        client: HttpClient,
        time_delay: int = 5,
        on_event: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.client = client
        self.time_delay = time_delay
        # Optional progress callback (the CLI passes a Rich logger).
        self._emit = on_event or (lambda _msg: None)

    def scan(self, req: Request, only_params: Optional[List[str]] = None) -> List[Finding]:
        points = req.injection_points(only=only_params)
        if not points:
            self._emit("No injectable parameters found in the request.")
            return []

        self._emit(f"Baseline request -> {req.method} {req.url}")
        baseline = self.client.baseline(req)
        self._emit(
            f"Baseline: status={baseline.status} len={baseline.length} "
            f"time={baseline.elapsed:.2f}s"
        )

        findings: List[Finding] = []
        for point in points:
            self._emit(f"Testing parameter: {point.param} ({point.location})")
            finding = self._test_point(req, point, baseline)
            if finding:
                # ML triage refines confidence; deterministic detection already decided.
                triage_finding(finding)
                findings.append(finding)
                self._emit(
                    f"  [+] {point.param}: {finding.technique} "
                    f"(dbms={finding.dbms or 'unknown'}, conf={finding.confidence:.2f})"
                )
            else:
                self._emit(f"  [-] {point.param}: not injectable")
        return findings

    def _test_point(self, req: Request, point, baseline) -> Optional[Finding]:
        for detector_cls in ALL_DETECTORS:
            if detector_cls is TimeBasedDetector:
                detector = detector_cls(self.client, baseline, delay=self.time_delay)
            else:
                detector = detector_cls(self.client, baseline)
            finding = detector.test(req, point)
            if finding:
                return finding
        return None
