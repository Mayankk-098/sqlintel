"""A tiny intentionally-vulnerable HTTP server for end-to-end testing SQLintel.

Simulates a MySQL-backed endpoint:
  * error-based : a single quote in `id` surfaces a MySQL error string
  * boolean     : "1=1" (true) returns the record; "1=2" (false) returns empty
  * time-based  : a SLEEP(n) payload actually sleeps n seconds

Run:  python tests/mock_vuln_server.py 8099
Then: sqlintel -u "http://127.0.0.1:8099/item?id=1" -p id --batch
"""

import re
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

MYSQL_ERROR = (
    "You have an error in your SQL syntax; check the manual that corresponds "
    "to your MySQL server version for the right syntax"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):  # silence noisy logging
        pass

    def do_GET(self):
        qs = parse_qs(urlparse(self.path).query, keep_blank_values=True)
        raw = qs.get("id", ["1"])[0]

        # time-based: honor SLEEP(n) / WAITFOR DELAY '0:0:n'
        m = re.search(r"sleep\((\d+)\)", raw, re.IGNORECASE) or re.search(
            r"waitfor\s+delay\s+'0:0:(\d+)'", raw, re.IGNORECASE
        )
        if m:
            time.sleep(int(m.group(1)))

        # error-based: unbalanced quote breaks the "query"
        if raw.count("'") % 2 == 1:
            return self._send(f"<html><body>{MYSQL_ERROR}</body></html>")

        # boolean-based: emulate WHERE id=<raw>. TRUE shows the record, FALSE hides it.
        false_condition = re.search(r"1\s*=\s*2", raw) or re.search(
            r"'1'\s*=\s*'2'", raw
        )
        if false_condition:
            return self._send("<html><body>No results found.</body></html>")

        return self._send(
            "<html><body>Product #1: Blue Widget — in stock. "
            "Full description here.</body></html>"
        )

    def _send(self, body: str):
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
