"""Run the benchmark end to end: (optionally) spin up the mock server, score each
available tool, tear the server down, and write results.md + results.json.

    python -m benchmark.run_benchmark                      # mock suite, all tools
    python -m benchmark.run_benchmark --tools sqlintel     # SQLintel only
    python -m benchmark.run_benchmark --target-set dvwa --base-url http://127.0.0.1:8080

Only the bundled mock server and DVWA/Juice Shop are legitimate targets — never point
this at anything you are not authorized to test.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from typing import List, Optional

from .harness import detect_tools, render_markdown, render_table, run_tool
from .targets import TARGET_SETS

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_MOCK_SERVER = os.path.join(_ROOT, "tests", "mock_vuln_server.py")


def _wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    """Poll until the server accepts a TCP connection, or give up after `timeout`."""
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _start_mock_server(port: int) -> subprocess.Popen:
    proc = subprocess.Popen(
        [sys.executable, _MOCK_SERVER, str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if not _wait_for_port("127.0.0.1", port):
        proc.terminate()
        raise RuntimeError(f"mock server did not come up on port {port}")
    return proc


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="benchmark", description=__doc__)
    p.add_argument("--tools", default="sqlintel,sqlmap,ghauri",
                   help="Comma-separated tools to compare (default: all three)")
    p.add_argument("--target-set", choices=sorted(TARGET_SETS), default="mock",
                   help="Which labeled target set to run (default: mock)")
    p.add_argument("--base-url", default=None,
                   help="Base URL for the target set (default: mock -> local server, "
                        "dvwa -> http://127.0.0.1:8080)")
    p.add_argument("--port", type=int, default=8099, help="Port for the mock server")
    p.add_argument("--timeout", type=float, default=120.0,
                   help="Per-scan timeout in seconds (default: 120)")
    p.add_argument("--cookie", default=None,
                   help="Session cookie for authed targets, e.g. "
                        "'PHPSESSID=<id>; security=low' (required for DVWA)")
    p.add_argument("--out", default=_HERE, help="Directory for results.md / results.json")
    args = p.parse_args(argv)

    requested = [t.strip() for t in args.tools.split(",") if t.strip()]
    available, skipped = detect_tools(requested)
    if skipped:
        print(f"[skip] not installed, excluded from run: {', '.join(skipped)}")
    if not available:
        print("[error] no requested tools are available.")
        return 2

    targets = TARGET_SETS[args.target_set]

    server = None
    if args.target_set == "mock":
        base_url = args.base_url or f"http://127.0.0.1:{args.port}"
        if not args.base_url:  # only manage the server if the user didn't point elsewhere
            print(f"[setup] starting mock server on {base_url} ...")
            server = _start_mock_server(args.port)
    else:
        base_url = args.base_url or "http://127.0.0.1:8080"

    if args.target_set == "dvwa" and not args.cookie:
        print("[warn] DVWA targets are auth-gated; without --cookie the tools will be "
              "redirected to the login page and every target will read as not-vulnerable. "
              "Pass --cookie 'PHPSESSID=<id>; security=low'.")

    print(f"[run] target-set={args.target_set} base={base_url} "
          f"tools={','.join(available)}\n")

    results = []
    try:
        for name in available:
            print(f"[{name}]")
            results.append(run_tool(name, base_url, targets, args.timeout,
                                    on_event=print, cookie=args.cookie))
            print("")
    finally:
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
            print("[teardown] mock server stopped.")

    print("\n" + render_table(results) + "\n")

    os.makedirs(args.out, exist_ok=True)
    md_path = os.path.join(args.out, "results.md")
    json_path = os.path.join(args.out, "results.json")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(render_markdown(results, base_url, args.target_set, skipped))
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(
            {"target_set": args.target_set, "base_url": base_url,
             "skipped": skipped, "results": results},
            fh, indent=2,
        )
    print(f"[out] wrote {md_path}")
    print(f"[out] wrote {json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
