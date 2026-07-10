"""Turn a captured network request / form into a normalized `Request`, and give each
one a canonical de-duplication key.

Browser-free and pure so it can be unit-tested with synthetic records — the crawler
feeds it real captures at runtime.

A captured record is a plain dict:
    {
        "method":       "GET" | "POST" | ...,
        "url":          "http://host/path?a=1",     # may include a query string
        "post_data":    "a=1&b=2" | '{"id":1}' | None,
        "content_type": "application/json" | "application/x-www-form-urlencoded" | "",
    }
"""

from __future__ import annotations

import json
from typing import Dict, Optional
from urllib.parse import parse_qsl, urlparse, urlunparse

from ..core.target import Request

# JSON scalars we treat as injectable leaves. Nested objects/arrays are skipped in v1.
_JSON_SCALARS = (str, int, float, bool)


def build_request(captured: dict) -> Optional[Request]:
    """Build a `Request` from one captured record, or None if it has nothing to inject."""
    method = (captured.get("method") or "GET").upper()
    raw_url = captured.get("url") or ""
    parsed = urlparse(raw_url)

    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    url = urlunparse(parsed._replace(query=""))

    body: Dict[str, str] = {}
    body_type = "form"
    post_data = captured.get("post_data")
    content_type = (captured.get("content_type") or "").lower()

    if post_data:
        if "application/json" in content_type:
            body, body_type = _json_body(post_data), "json"
        else:
            # Default non-JSON bodies to form-encoded (covers the common case).
            body = dict(parse_qsl(post_data, keep_blank_values=True))
            body_type = "form"

    # Nothing user-controllable to mutate → not an injection surface.
    if not query and not body:
        return None

    return Request(
        method=method,
        url=url,
        query=query,
        body=body,
        body_type=body_type,
    )


def _json_body(post_data: str) -> Dict[str, str]:
    """Extract top-level scalar fields from a JSON body as string values."""
    try:
        obj = json.loads(post_data)
    except (ValueError, TypeError):
        return {}
    if not isinstance(obj, dict):
        return {}
    out: Dict[str, str] = {}
    for key, val in obj.items():
        if isinstance(val, bool) or isinstance(val, (str, int, float)):
            out[key] = str(val)
    return out


def endpoint_key(req: Request) -> str:
    """Canonical key collapsing requests that share the same injection surface.

    Keyed on method + path + the *set of parameter names* (not their values), so
    /item?id=1 and /item?id=2 dedup to a single endpoint worth scanning once.
    """
    path = urlparse(req.url).path
    params = sorted(list(req.query.keys()) + list(req.body.keys()))
    return f"{req.method} {path} [{','.join(params)}]"
