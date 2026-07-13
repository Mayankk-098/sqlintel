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
    # Set when the request failed (timeout, reset, DNS, etc.). Such a response is
    # "inconclusive": detectors must skip it rather than treat it as a real answer.
    error: Optional[str] = None

    @property
    def length(self) -> int:
        return len(self.text)

    @property
    def ok(self) -> bool:
        return self.error is None


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
        cookies = dict(req.cookies)
        headers = dict(req.headers)
        if mutation:
            for key, val in mutation.items():
                # Apply to whichever location already holds the param, so cookie/header
                # injection points are mutated in place rather than leaking into the query.
                if key in query:
                    query[key] = val
                elif key in body:
                    body[key] = val
                elif key in cookies:
                    cookies[key] = val
                elif key in headers:
                    headers[key] = val
                else:
                    # New/unknown param: default to query string.
                    query[key] = val

        if self.delay:
            time.sleep(self.delay)

        # Serialize the body per its declared type. JSON endpoints (captured by the
        # crawler) need `json=` so httpx sets Content-Type: application/json and encodes
        # the dict as a JSON object; form endpoints keep the urlencoded `data=` path.
        send_kwargs = {}
        if body:
            if req.body_type == "json":
                send_kwargs["json"] = body
            else:
                send_kwargs["data"] = body

        start = time.perf_counter()
        try:
            resp = self._client.request(
                req.method,
                req.url,
                params=query or None,
                cookies=cookies or None,
                headers=headers or None,
                **send_kwargs,
            )
        except httpx.HTTPError as exc:
            # A timeout / reset / DNS failure on one probe must not kill the whole scan.
            # Return an inconclusive response with elapsed=0.0 so it can never be mistaken
            # for a time-based delay; detectors skip responses where `.ok` is False.
            return Response(status=0, text="", elapsed=0.0, headers={}, error=str(exc))
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
