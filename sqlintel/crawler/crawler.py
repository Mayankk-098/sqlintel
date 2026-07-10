"""Playwright-driven crawler: discover injection surfaces by *running* the app.

Unlike an HTML-only crawler, this captures the XHR/fetch/API calls a single-page app
makes at runtime (via a network-request listener) in addition to parsing `<a>` links
and `<form>`s. The output is a de-duplicated list of `Request` objects handed straight
to the existing deterministic engine — the crawler never decides anything about
vulnerability, it only expands the attack surface.

Playwright is an *optional* dependency (`pip install -e .[crawl]` + `playwright install
chromium`). Import is lazy so the core scanner runs with Playwright absent; callers should
check `PLAYWRIGHT_AVAILABLE` before constructing a `Crawler`.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional
from urllib.parse import urldefrag, urlencode

from ..core.target import Request
from .builder import build_request, endpoint_key
from .scope import Scope

try:  # cheap availability probe — does not import the heavy sync API
    import playwright  # noqa: F401

    PLAYWRIGHT_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on optional install
    PLAYWRIGHT_AVAILABLE = False


# JavaScript run in-page to pull every form's method, resolved action, and field names.
_FORM_EXTRACT_JS = """
() => Array.from(document.querySelectorAll('form')).map(f => ({
  method: (f.getAttribute('method') || 'GET').toUpperCase(),
  action: f.action || location.href,
  fields: Array.from(f.querySelectorAll('input[name], select[name], textarea[name]'))
             .map(e => ({name: e.name, value: (e.value || '1')}))
}))
"""


@dataclass
class CrawlConfig:
    scope: Scope
    max_pages: int = 25
    max_depth: int = 3
    timeout_s: float = 15.0
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)


class Crawler:
    def __init__(
        self,
        config: CrawlConfig,
        on_event: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.cfg = config
        self._emit = on_event or (lambda _msg: None)
        # endpoint_key -> Request, so shared surfaces are scanned once.
        self._discovered: Dict[str, Request] = {}

    def crawl(self, seed_url: str) -> List[Request]:
        if not PLAYWRIGHT_AVAILABLE:  # pragma: no cover - guarded by CLI beforehand
            raise RuntimeError(
                "Playwright is not installed. Run: pip install -e .[crawl] "
                "&& playwright install chromium"
            )
        from playwright.sync_api import sync_playwright

        timeout_ms = int(self.cfg.timeout_s * 1000)
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context()
            if self.cfg.headers:
                context.set_extra_http_headers(self.cfg.headers)
            if self.cfg.cookies:
                context.add_cookies(
                    [
                        {"name": k, "value": v, "url": seed_url}
                        for k, v in self.cfg.cookies.items()
                    ]
                )

            page = context.new_page()
            # Capture every network request the page issues (documents, XHR, fetch).
            page.on("request", self._on_request)

            self._bfs(page, seed_url, timeout_ms)

            context.close()
            browser.close()

        return list(self._discovered.values())

    # --- internals -------------------------------------------------------------

    def _on_request(self, request) -> None:
        """Playwright request listener → record in-scope requests as candidate surfaces."""
        try:
            url = request.url
            if not self.cfg.scope.should_visit(url):
                return
            content_type = request.headers.get("content-type", "")
            self._add(
                {
                    "method": request.method,
                    "url": url,
                    "post_data": request.post_data,
                    "content_type": content_type,
                }
            )
        except Exception:
            # A single unreadable request must never abort the crawl.
            return

    def _bfs(self, page, seed_url: str, timeout_ms: int) -> None:
        queue = deque([(seed_url, 0)])
        visited: set[str] = set()

        while queue and len(visited) < self.cfg.max_pages:
            url, depth = queue.popleft()
            url = urldefrag(url)[0]  # ignore #fragments for visited-tracking
            if url in visited or depth > self.cfg.max_depth:
                continue
            visited.add(url)
            self._emit(f"Crawling [{len(visited)}/{self.cfg.max_pages}] d={depth} {url}")

            try:
                page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                # Give SPA XHR/fetch time to fire; ignore idle-timeout, we captured live.
                try:
                    page.wait_for_load_state("networkidle", timeout=timeout_ms)
                except Exception:
                    pass
            except Exception as exc:
                self._emit(f"  skip (nav failed): {exc}")
                continue

            self._harvest_forms(page)

            if depth < self.cfg.max_depth:
                for link in self._page_links(page):
                    if self.cfg.scope.should_visit(link) and urldefrag(link)[0] not in visited:
                        queue.append((link, depth + 1))

    def _page_links(self, page) -> List[str]:
        try:
            return page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href)"
            ) or []
        except Exception:
            return []

    def _harvest_forms(self, page) -> None:
        try:
            forms = page.evaluate(_FORM_EXTRACT_JS) or []
        except Exception:
            return
        for form in forms:
            fields = {f["name"]: f.get("value", "1") for f in form.get("fields", []) if f.get("name")}
            if not fields:
                continue
            method = (form.get("method") or "GET").upper()
            action = form.get("action") or ""
            if method == "GET":
                sep = "&" if "?" in action else "?"
                self._add({"method": "GET", "url": f"{action}{sep}{urlencode(fields)}"})
            else:
                self._add(
                    {
                        "method": method,
                        "url": action,
                        "post_data": urlencode(fields),
                        "content_type": "application/x-www-form-urlencoded",
                    }
                )

    def _add(self, captured: dict) -> None:
        req = build_request(captured)
        if req is None:
            return
        key = endpoint_key(req)
        if key not in self._discovered:
            self._discovered[key] = req
            self._emit(f"  + endpoint: {key}")
