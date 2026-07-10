"""Crawl scope rules — decide which URLs are in-bounds.

Kept free of any browser dependency so it can be unit-tested directly. The default is
same-origin (scheme + host + port must match the seed), with optional include/exclude
regex filters layered on top.
"""

from __future__ import annotations

import re
from typing import List, Optional, Pattern
from urllib.parse import urlparse


def _origin(url: str) -> tuple[str, str, int]:
    """(scheme, host, port) with the scheme's default port filled in."""
    p = urlparse(url)
    port = p.port or (443 if p.scheme == "https" else 80)
    return (p.scheme, (p.hostname or "").lower(), port)


class Scope:
    def __init__(
        self,
        seed_url: str,
        include: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
        same_origin: bool = True,
    ) -> None:
        self.seed_origin = _origin(seed_url)
        self.same_origin = same_origin
        self._include: List[Pattern[str]] = [re.compile(p) for p in (include or [])]
        self._exclude: List[Pattern[str]] = [re.compile(p) for p in (exclude or [])]

    def should_visit(self, url: str) -> bool:
        if not url.startswith(("http://", "https://")):
            return False
        if self.same_origin and _origin(url) != self.seed_origin:
            return False
        if self._exclude and any(rx.search(url) for rx in self._exclude):
            return False
        if self._include and not any(rx.search(url) for rx in self._include):
            return False
        return True
