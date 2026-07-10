"""SPA/API-aware crawler that discovers injection surfaces for the engine to scan."""

from .builder import build_request, endpoint_key
from .crawler import PLAYWRIGHT_AVAILABLE, CrawlConfig, Crawler
from .scope import Scope

__all__ = [
    "Crawler",
    "CrawlConfig",
    "Scope",
    "PLAYWRIGHT_AVAILABLE",
    "build_request",
    "endpoint_key",
]
