"""Build a normalized `Request` from a URL (`-u`) or a raw request file (`-r`).

The raw-request format matches what you get from "Copy to file" in Burp / browser
devtools, so users can replay authenticated, stateful requests — the same ergonomics
that make sqlmap/Ghauri's `-r` so useful.
"""

from __future__ import annotations

from typing import Dict
from urllib.parse import parse_qsl, urlparse, urlunparse

from .target import Request


def from_url(url: str, method: str = "GET", data: str = "") -> Request:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    # Strip the query off the stored URL; we re-attach params at send time.
    clean = urlunparse(parsed._replace(query=""))
    body = dict(parse_qsl(data, keep_blank_values=True)) if data else {}
    if body and method.upper() == "GET":
        method = "POST"
    return Request(method=method.upper(), url=clean, query=query, body=body)


def from_raw_file(path: str, force_https: bool = False) -> Request:
    """Parse a raw HTTP request saved to disk.

    Example file contents:
        POST /login HTTP/1.1
        Host: example.com
        Cookie: session=abc
        Content-Type: application/x-www-form-urlencoded

        user=admin&pass=1
    """
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        raw = fh.read()

    # Split headers from body on the first blank line.
    if "\r\n\r\n" in raw:
        head, _, body_str = raw.partition("\r\n\r\n")
    else:
        head, _, body_str = raw.partition("\n\n")

    lines = head.splitlines()
    if not lines:
        raise ValueError(f"{path}: empty request file")

    method, path_and_query, *_ = lines[0].split()

    headers: Dict[str, str] = {}
    cookies: Dict[str, str] = {}
    host = ""
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name, value = name.strip(), value.strip()
        low = name.lower()
        if low == "host":
            host = value
        elif low == "cookie":
            for pair in value.split(";"):
                if "=" in pair:
                    k, _, v = pair.strip().partition("=")
                    cookies[k] = v
        else:
            headers[name] = value

    scheme = "https" if force_https else "http"
    parsed = urlparse(f"{scheme}://{host}{path_and_query}")
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    url = urlunparse(parsed._replace(query=""))
    body = dict(parse_qsl(body_str.strip(), keep_blank_values=True)) if body_str.strip() else {}

    return Request(
        method=method.upper(),
        url=url,
        headers=headers,
        query=query,
        body=body,
        cookies=cookies,
    )
