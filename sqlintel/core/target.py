"""Data models describing what to scan and what we found."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Cookies that carry session/auth/CSRF state — fuzzing them just breaks the session,
# so they're excluded from automatic injection-point enumeration.
_SKIP_COOKIES = {
    "phpsessid", "jsessionid", "asp.net_sessionid", "sessionid", "session", "sid",
    "csrftoken", "csrf", "csrf_token", "xsrf-token", "_csrf", "auth", "token",
}
# Attacker-controllable headers that realistically reach SQL sinks (logging, geo, etc.).
_INJECTABLE_HEADERS = {
    "user-agent", "referer", "x-forwarded-for", "x-forwarded-host",
    "x-client-ip", "true-client-ip", "x-real-ip",
}


@dataclass
class InjectionPoint:
    """A single place a payload can be injected: one parameter of one request."""

    param: str
    # The baseline (original) value of this parameter.
    value: str
    # Where the parameter lives, so we can rebuild the request when mutating it.
    location: str = "query"  # "query" | "body" | "cookie" | "header"


@dataclass
class Request:
    """A normalized HTTP request that the engine can mutate and replay.

    Built either from a URL (`-u`) or a saved raw request file (`-r`).
    """

    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    query: Dict[str, str] = field(default_factory=dict)
    body: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    # How the body is serialized on the wire: "form" (x-www-form-urlencoded) or "json".
    # The crawler sets "json" for captured REST/API endpoints; everything else stays form.
    body_type: str = "form"

    def injection_points(self, only: Optional[List[str]] = None) -> List[InjectionPoint]:
        """Enumerate candidate injection points across query and body params.

        `only` restricts to a user-specified subset (the `-p` flag).
        """
        points: List[InjectionPoint] = []
        for name, val in self.query.items():
            points.append(InjectionPoint(param=name, value=val, location="query"))
        for name, val in self.body.items():
            points.append(InjectionPoint(param=name, value=val, location="body"))
        # Cookies and headers are real SQLi sinks too (X-Forwarded-For, cookie values),
        # but blindly fuzzing session cookies / every header is noisy and breaks auth —
        # so we skip session-like cookies and only test a curated set of headers.
        for name, val in self.cookies.items():
            if name.lower() not in _SKIP_COOKIES:
                points.append(InjectionPoint(param=name, value=val, location="cookie"))
        for name, val in self.headers.items():
            if name.lower() in _INJECTABLE_HEADERS:
                points.append(InjectionPoint(param=name, value=val, location="header"))
        if only:
            wanted = {p.strip() for p in only}
            points = [p for p in points if p.param in wanted]
        return points


@dataclass
class Finding:
    """A confirmed-or-suspected SQL injection at one injection point."""

    injection_point: InjectionPoint
    technique: str  # "error-based" | "boolean-based" | "time-based"
    # The endpoint this finding was found at — filled in by the engine. Matters in crawl
    # mode where one scan spans many endpoints; empty for a single -u/-r target.
    url: str = ""
    dbms: Optional[str] = None
    payload: str = ""
    evidence: str = ""
    # 0..1 — deterministic confidence now; the ML layer will refine this later.
    confidence: float = 0.0
    proven: bool = False

    @property
    def severity(self) -> str:
        # SQLi is high/critical by nature; proof bumps it to critical.
        return "critical" if self.proven else "high"
