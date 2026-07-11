"""A tiny intentionally-vulnerable HTTP server for end-to-end testing SQLintel.

Simulates a MySQL-backed shop:
  * error-based : a single quote in `id` surfaces a MySQL error string
  * boolean     : "1=1" (true) returns the record; "1=2" (false) returns empty
  * time-based  : a SLEEP(n) payload actually sleeps n seconds

Routes:
  GET  /              -> an index page with a link, a <form>, and a JS fetch() to the API
                         (so the Playwright crawler has links/forms/XHR to discover)
  GET  /item?id=1     -> HTML product lookup (classic query-param sink)
  POST /api/item      -> JSON API lookup; body {"id": 1} (REST/JSON body sink)
  GET  /safe/item?id=1-> SAFE: ignores input, constant reply (a benchmark true negative)
  POST /safe/api/item -> SAFE JSON: ignores input, constant reply (true negative)

Run:  python tests/mock_vuln_server.py 8099
Then: sqlintel -u "http://127.0.0.1:8099/item?id=1" -p id --batch
  or: sqlintel -u "http://127.0.0.1:8099/" --crawl --batch
"""

import json
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

MYSQL_ERROR = (
    "You have an error in your SQL syntax; check the manual that corresponds "
    "to your MySQL server version for the right syntax"
)

_INDEX_HTML = """<html><body>
  <h1>Widget Shop</h1>
  <a href="/item?id=1">Product 1</a>
  <form action="/item" method="GET">
    <input name="id" value="1"><button type="submit">Search</button>
  </form>
  <div id="api"></div>
  <script>
    // SPA-style API call the crawler must capture (not present in static HTML links).
    fetch('/api/item', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({id: 1})
    });
  </script>
</body></html>"""


_PRODUCT = "Product #1: Blue Widget - in stock. Full description here."
_EMPTY = "No results found."

# Only a purely-numeric boolean expression is safe to evaluate; anything with quotes,
# letters (SLEEP, column names) or other syntax is something this toy doesn't model.
_NUMERIC_BOOL = re.compile(r"[^0-9\s()<>=!]")


def _balance_parens(expr: str) -> str:
    """Rebalance parentheses so a `1) AND ... AND (1=1` boundary evaluates as valid.

    sqlmap/Ghauri confirm injections with a parenthesis boundary that assumes the real
    query wraps the value like `WHERE (id = <raw>)`. We restore that wrapping by adding a
    matching `(` for every unmatched `)` and a matching `)` for every unmatched `(`.
    """
    open_count = need_open = 0
    for ch in expr:
        if ch == "(":
            open_count += 1
        elif ch == ")":
            if open_count:
                open_count -= 1
            else:
                need_open += 1
    return "(" * need_open + expr + ")" * open_count


def _row_matches(raw: str) -> bool:
    """Simulate ``SELECT ... WHERE (id = <raw>)`` for the one row whose id is 1.

    We evaluate the injected boolean tail the way a real numeric query would, so
    ``AND 1=1`` / ``AND <rand>=<rand>`` (TRUE) and ``AND 1=2`` / ``AND <rand>=<rand+1>``
    (FALSE) produce consistently different pages, and the parenthesis-boundary variants
    the scanners use for their false-positive check evaluate correctly too. That fidelity
    is what lets sqlmap and Ghauri *confirm* the injection instead of rejecting it as a
    false positive — the point of a fair benchmark oracle, not a string-match toy.
    """
    # Strip SQL comments so `... 1=1-- -` evaluates as `... 1=1`.
    expr = re.sub(r"/\*.*?\*/", " ", raw, flags=re.DOTALL)
    expr = re.split(r"--\s|#", expr, maxsplit=1)[0]

    # Substitute the row's own id (1) for the column, then rebalance injected parens.
    clause = _balance_parens("1 = " + expr)
    clause = re.sub(r"\bAND\b", " and ", clause, flags=re.IGNORECASE)
    clause = re.sub(r"\bOR\b", " or ", clause, flags=re.IGNORECASE)
    clause = re.sub(r"\bNOT\b", " not ", clause, flags=re.IGNORECASE)
    clause = clause.replace("<>", "!=")
    # Turn SQL `=` into Python `==` without touching `<=`, `>=`, `!=`, `==`.
    clause = re.sub(r"(?<![<>=!])=(?!=)", "==", clause)

    # Keep eval sandboxed: only pure-numeric boolean logic ever reaches it. Everything
    # else (quotes, functions, string literals) we can't model, so behave like baseline.
    probe = re.sub(r"\b(?:and|or|not)\b", " ", clause)
    if _NUMERIC_BOOL.search(probe):
        return True
    try:
        return bool(eval(clause, {"__builtins__": {}}, {}))  # noqa: S307 (toy oracle)
    except Exception:
        return True


def _result_text(raw: str) -> str:
    """Shared vulnerable 'query' logic → the message text for a given `id` value.

    Honors SLEEP()/WAITFOR (time-based), unbalanced quotes (error-based), and a real
    numeric boolean condition (boolean-based) so all scanners get a fair test.
    """
    m = re.search(r"sleep\((\d+)\)", raw, re.IGNORECASE) or re.search(
        r"waitfor\s+delay\s+'0:0:(\d+)'", raw, re.IGNORECASE
    )
    if m:
        time.sleep(int(m.group(1)))

    if raw.count("'") % 2 == 1:  # unbalanced quote breaks the query
        return MYSQL_ERROR

    return _PRODUCT if _row_matches(raw) else _EMPTY


# A constant reply for the SAFE endpoints: input is never reflected into a query, so a
# quote yields no error, 1=1/1=2 look identical, and SLEEP() never delays. These endpoints
# exist so the benchmark has true negatives to measure the false-positive rate against.
_SAFE_REPLY = "Product #1: Blue Widget - in stock. Full description here."


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):  # silence noisy logging
        pass

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            return self._send(_INDEX_HTML, "text/html")

        # SAFE route first, so it never falls through to the vulnerable /item logic below.
        if path == "/safe/item":
            return self._send(f"<html><body>{_SAFE_REPLY}</body></html>", "text/html")

        qs = parse_qs(urlparse(self.path).query, keep_blank_values=True)
        raw = qs.get("id", ["1"])[0]
        return self._send(f"<html><body>{_result_text(raw)}</body></html>", "text/html")

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""

        # SAFE route first: read (and discard) the body, then reply with a constant.
        if path == "/safe/api/item":
            return self._send(json.dumps({"result": _SAFE_REPLY}), "application/json")

        if path == "/api/item":
            try:
                raw = str(json.loads(body.decode() or "{}").get("id", "1"))
            except (ValueError, TypeError):
                raw = "1"
            return self._send(json.dumps({"result": _result_text(raw)}), "application/json")

        return self._send("<html><body>Not found.</body></html>", "text/html")

    def _send(self, body: str, content_type: str):
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
