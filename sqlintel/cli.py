"""SQLintel command-line interface."""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from rich.console import Console

from . import __version__
from .core.engine import Engine
from .core.http_client import HttpClient
from .core.request_parser import from_raw_file, from_url
from .report.reporter import print_console, to_json

# Best-effort UTF-8 stdout on Windows so Rich never chokes on legacy code pages.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    except Exception:
        pass

console = Console()

_BANNER = r"""
   ____   ___  _     _       _       _
  / ___| / _ \| |   (_)_ __ | |_ ___| |
  \___ \| | | | |   | | '_ \| __/ _ \ |
   ___) | |_| | |___| | | | | ||  __/ |
  |____/ \__\_\_____|_|_| |_|\__\___|_|   AI-augmented SQLi scanner v{ver}
""".format(ver=__version__)

_AUTHORIZATION_NOTICE = (
    "Only scan systems you own or have WRITTEN authorization to test. "
    "Unauthorized scanning may be illegal."
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sqlintel",
        description="AI-augmented SQL injection vulnerability scanner.",
        epilog=_AUTHORIZATION_NOTICE,
    )
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("-u", "--url", help="Target URL, e.g. 'http://host/item?id=1'")
    target.add_argument("-r", "--request-file", help="Raw HTTP request file (Burp-style)")

    p.add_argument("-p", "--param", help="Comma-separated params to test (default: all)")
    p.add_argument("-m", "--method", default="GET", help="HTTP method for -u (default: GET)")
    p.add_argument("-d", "--data", default="", help="POST body for -u, e.g. 'a=1&b=2'")
    p.add_argument("--force-https", action="store_true", help="Use https for -r targets")

    p.add_argument("--proxy", help="Proxy URL, e.g. http://127.0.0.1:8080")
    p.add_argument("--timeout", type=float, default=30.0, help="Per-request timeout (s)")
    p.add_argument("--delay", type=float, default=0.0, help="Delay between requests (s)")
    p.add_argument("--time-sec", type=int, default=5, help="Sleep seconds for time-based test")
    p.add_argument("-k", "--insecure", action="store_true", help="Skip TLS verification")
    p.add_argument("-H", "--header", action="append", default=[],
                   help="Extra header 'Name: value' (repeatable)")

    p.add_argument("--json", metavar="PATH", help="Write JSON report to PATH")
    p.add_argument("--batch", action="store_true",
                   help="Non-interactive: assume authorization confirmed")
    p.add_argument("-q", "--quiet", action="store_true", help="Suppress progress output")
    p.add_argument("-V", "--version", action="version", version=f"SQLintel {__version__}")
    return p


def _parse_headers(items: List[str]) -> dict:
    headers = {}
    for item in items:
        if ":" in item:
            name, _, value = item.partition(":")
            headers[name.strip()] = value.strip()
    return headers


def _confirm_authorization(batch: bool) -> bool:
    if batch:
        return True
    console.print(f"[yellow]{_AUTHORIZATION_NOTICE}[/yellow]")
    try:
        answer = input("Do you have authorization to scan this target? [y/N] ").strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes")


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.quiet:
        console.print(f"[bold cyan]{_BANNER}[/bold cyan]")

    if not _confirm_authorization(args.batch):
        console.print("[red]Authorization not confirmed. Aborting.[/red]")
        return 2

    # Build the request from either -u or -r.
    if args.url:
        req = from_url(args.url, method=args.method, data=args.data)
        target_desc = args.url
    else:
        req = from_raw_file(args.request_file, force_https=args.force_https)
        target_desc = args.request_file

    extra_headers = _parse_headers(args.header)
    only_params = args.param.split(",") if args.param else None

    emit = (lambda msg: None) if args.quiet else (lambda msg: console.print(f"[dim]{msg}[/dim]"))

    with HttpClient(
        timeout=args.timeout,
        proxy=args.proxy,
        verify_tls=not args.insecure,
        extra_headers=extra_headers,
        delay=args.delay,
    ) as client:
        engine = Engine(client, time_delay=args.time_sec, on_event=emit)
        try:
            findings = engine.scan(req, only_params=only_params)
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted.[/yellow]")
            return 130

    print_console(findings, console)

    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(to_json(findings, target_desc))
        if not args.quiet:
            console.print(f"\n[green]JSON report written to {args.json}[/green]")

    # Exit non-zero when findings exist → CI/CD gates can fail the build.
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
