"""Thin synchronous HTTP wrapper around httpx.

Kept sync for MVP simplicity — detection is I/O bound but the logic is far easier to
read and debug without async. We can swap to httpx.AsyncClient later without changing
the detector interfaces (they only call `send`).
"""

from __future__ import annotations

import copy
import time
from dataclasses import dataclass
from typing import Dict, Optional

import httpx

from .target import Request


@dataclass
class Response:
    status: int
    text: str
    elapsed: float  # seconds, wall-clock — used by the time-based detector
    headers: Dict[str, str]

    @property
    def length(self) -> int:
        return len(self.text)


class HttpClient:
    def __init__(
        self,
        timeout: float = 30.0,
        proxy: Optional[str] = None,
        verify_tls: bool = True,
        extra_headers: Optional[Dict[str, str]] = None,
        delay: float = 0.0,
    ) -> None:
        self.delay = delay
        default_headers = {
            "User-Agent": "SQLintel/0.1 (+https://github.com/mayan/sqlintel)",
        }
        if extra_headers:
            default_headers.update(extra_headers)
        self._client = httpx.Client(
            timeout=timeout,
            proxy=proxy,
            verify=verify_tls,
            headers=default_headers,
            follow_redirects=True,
        )

    def send(self, req: Request, mutation: Optional[Dict[str, str]] = None) -> Response:
        """Send `req`, optionally overriding one param via `mutation={param: value}`.

        The mutation is applied to whichever location (query/body) holds the param.
        Timing is measured here so time-based detection uses a consistent clock.
        """
        query = dict(req.query)
        body = dict(req.body)
        if mutation:
            for key, val in mutation.items():
                if key in query:
                    query[key] = val
                elif key in body:
                    body[key] = val
                else:
                    # New/unknown param: default to query string.
                    query[key] = val

        if self.delay:
            time.sleep(self.delay)

        start = time.perf_counter()
        resp = self._client.request(
            req.method,
            req.url,
            params=query or None,
            data=body or None,
            cookies=req.cookies or None,
            headers=req.headers or None,
        )
        elapsed = time.perf_counter() - start
        return Response(
            status=resp.status_code,
            text=resp.text,
            elapsed=elapsed,
            headers=dict(resp.headers),
        )

    def baseline(self, req: Request) -> Response:
        """Unmodified request — the reference every detector compares against."""
        return self.send(copy.deepcopy(req))

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()
