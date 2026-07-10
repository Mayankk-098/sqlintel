"""Scan orchestration: for each injection point, run each detector until one fires.

This is the deterministic core. The ML layer (sqlintel.ml) plugs in here later to
(a) rank injection points before scanning and (b) re-score findings for FP triage —
but it never replaces the detectors' verdict.
"""

from __future__ import annotations

from typing import Callable, List, Optional

from ..detectors import ALL_DETECTORS, TimeBasedDetector
from ..ml.triage import triage_finding
from ..verify import ProofVerifier
from .http_client import HttpClient
from .target import Finding, Request


class Engine:
    def __init__(
        self,
        client: HttpClient,
        time_delay: int = 5,
        verify: bool = True,
        on_event: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.client = client
        self.time_delay = time_delay
        self.verify = verify
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
                # Tag the finding with its endpoint so crawl-mode reports can attribute
                # each finding to the right URL (harmless for single -u/-r targets).
                finding.url = req.url
                # 1) Proof-based verification re-confirms independently (sets proven).
                if self.verify:
                    ProofVerifier(self.client, baseline).verify(req, finding)
                # 2) ML triage refines confidence; deterministic detection already decided.
                triage_finding(finding)
                findings.append(finding)
                self._emit(
                    f"  [+] {point.param}: {finding.technique} "
                    f"(dbms={finding.dbms or 'unknown'}, conf={finding.confidence:.2f}, "
                    f"proven={finding.proven})"
                )
            else:
                self._emit(f"  [-] {point.param}: not injectable")
        return findings

    def scan_many(self, requests: List[Request]) -> List[Finding]:
        """Scan a batch of requests (e.g. a crawl result) and aggregate all findings.

        Each request gets its own baseline inside `scan()`; findings carry their `url`.
        """
        all_findings: List[Finding] = []
        total = len(requests)
        for idx, req in enumerate(requests, start=1):
            self._emit(f"[{idx}/{total}] Scanning {req.method} {req.url}")
            all_findings.extend(self.scan(req))
        return all_findings

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
