"""Browser-free unit tests for the crawler's pure logic.

These exercise scope rules, endpoint de-duplication, and captured-record -> Request
conversion (including the JSON-body path) without launching Playwright, so they stay
fast and run everywhere. A live browser smoke test lives at the bottom, skipped unless
Playwright is installed.
"""

from __future__ import annotations

import httpx
import pytest

from sqlintel.core.http_client import HttpClient
from sqlintel.core.target import Request
from sqlintel.crawler import PLAYWRIGHT_AVAILABLE, Scope, build_request, endpoint_key


# --- Scope -------------------------------------------------------------------

def test_scope_same_origin_allows_and_blocks():
    scope = Scope("http://site.test/app")
    assert scope.should_visit("http://site.test/app/other")
    assert not scope.should_visit("http://evil.test/app")  # different host
    assert not scope.should_visit("https://site.test/app")  # different scheme/port
    assert not scope.should_visit("mailto:x@y.z")  # non-http


def test_scope_include_exclude_regex():
    scope = Scope("http://site.test/", include=[r"/api/"], exclude=[r"/logout"])
    assert scope.should_visit("http://site.test/api/users")
    assert not scope.should_visit("http://site.test/home")  # fails include
    assert not scope.should_visit("http://site.test/api/logout")  # matches exclude


# --- endpoint_key dedup ------------------------------------------------------

def test_endpoint_key_collapses_same_surface():
    a = build_request({"method": "GET", "url": "http://h/item?id=1"})
    b = build_request({"method": "GET", "url": "http://h/item?id=2"})
    assert endpoint_key(a) == endpoint_key(b)  # same path + param names


def test_endpoint_key_distinguishes_param_sets():
    a = build_request({"method": "GET", "url": "http://h/item?id=1"})
    c = build_request({"method": "GET", "url": "http://h/item?id=1&sort=asc"})
    assert endpoint_key(a) != endpoint_key(c)  # different param set


# --- build_request -----------------------------------------------------------

def test_build_request_query_only():
    req = build_request({"method": "get", "url": "http://h/search?q=x&page=2"})
    assert req.method == "GET"
    assert req.url == "http://h/search"
    assert req.query == {"q": "x", "page": "2"}
    assert req.body == {} and req.body_type == "form"


def test_build_request_form_body():
    req = build_request(
        {
            "method": "POST",
            "url": "http://h/login",
            "post_data": "user=admin&pass=1",
            "content_type": "application/x-www-form-urlencoded",
        }
    )
    assert req.body == {"user": "admin", "pass": "1"}
    assert req.body_type == "form"


def test_build_request_json_body_extracts_top_level_scalars():
    req = build_request(
        {
            "method": "POST",
            "url": "http://h/api/items?debug=1",
            "post_data": '{"id": 5, "name": "a", "nested": {"x": 1}, "tags": [1, 2]}',
            "content_type": "application/json",
        }
    )
    assert req.body_type == "json"
    assert req.query == {"debug": "1"}
    # Scalars kept as strings; nested object and array dropped.
    assert req.body == {"id": "5", "name": "a"}


def test_build_request_no_params_returns_none():
    assert build_request({"method": "GET", "url": "http://h/home"}) is None


# --- http_client JSON branch -------------------------------------------------

def test_http_client_sends_json_for_json_body_type():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["content_type"] = request.headers.get("content-type", "")
        seen["body"] = request.content.decode()
        return httpx.Response(200, text="ok")

    client = HttpClient()
    # Swap in a mock transport so no real network call happens.
    client._client = httpx.Client(transport=httpx.MockTransport(handler))

    req = Request(method="POST", url="http://h/api", body={"id": "1"}, body_type="json")
    client.send(req, mutation={"id": "1' OR '1'='1"})

    assert "application/json" in seen["content_type"]
    assert '"id"' in seen["body"] and "OR" in seen["body"]
    client.close()


def test_http_client_sends_form_for_default_body_type():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["content_type"] = request.headers.get("content-type", "")
        return httpx.Response(200, text="ok")

    client = HttpClient()
    client._client = httpx.Client(transport=httpx.MockTransport(handler))

    req = Request(method="POST", url="http://h/login", body={"user": "a"})
    client.send(req)

    assert "application/x-www-form-urlencoded" in seen["content_type"]
    client.close()


# --- live browser smoke test (opt-in) ----------------------------------------

@pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="Playwright not installed")
def test_crawler_importable_with_playwright():
    # When Playwright is present, the sync API must import without error.
    from playwright.sync_api import sync_playwright  # noqa: F401
