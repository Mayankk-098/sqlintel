"""Render findings to the console and to JSON.

SARIF output (for GitHub code scanning / CI) is a planned Phase-2 addition; the JSON
schema here is intentionally close to a SARIF result so the mapping is small.
"""

from __future__ import annotations

import json
from typing import List

from rich import box
from rich.console import Console
from rich.table import Table

from ..core.target import Finding

# Language-agnostic remediation guidance keyed by DBMS. This is the free, templated
# alternative to an LLM remediation layer — reliable and $0.
_REMEDIATION = {
    "generic": (
        "Use parameterized queries / prepared statements instead of string concatenation. "
        "Validate and allow-list input; apply least-privilege DB accounts."
    ),
    "MySQL": "e.g. (PHP PDO) $stmt = $pdo->prepare('SELECT * FROM t WHERE id = ?'); $stmt->execute([$id]);",
    "PostgreSQL": "e.g. (psycopg) cur.execute('SELECT * FROM t WHERE id = %s', (id,))",
    "Microsoft SQL Server": "e.g. (C#) cmd.Parameters.AddWithValue(\"@id\", id);",
    "Oracle": "e.g. (cx_Oracle) cur.execute('SELECT * FROM t WHERE id = :id', id=id)",
    "SQLite": "e.g. (Python) cur.execute('SELECT * FROM t WHERE id = ?', (id,))",
}


def remediation_for(dbms: str) -> str:
    base = _REMEDIATION["generic"]
    specific = _REMEDIATION.get(dbms or "", "")
    return f"{base} {specific}".strip()


def print_console(findings: List[Finding], console: Console) -> None:
    if not findings:
        console.print("\n[bold green]No SQL injection findings.[/bold green]")
        return

    # Only show the Endpoint column in crawl mode (findings span >1 URL); single-target
    # output stays exactly as before.
    show_endpoint = len({f.url for f in findings if f.url}) > 1

    # ASCII box so output is safe on any console encoding (e.g. Windows cp1252).
    table = Table(title="SQLintel - Findings", show_lines=True, box=box.ASCII)
    if show_endpoint:
        table.add_column("Endpoint", style="blue", overflow="fold")
    table.add_column("Param", style="cyan", no_wrap=True)
    table.add_column("Technique", style="magenta")
    table.add_column("DBMS")
    table.add_column("Severity", style="bold")
    table.add_column("Conf.", justify="right")
    table.add_column("Proven", justify="center")
    table.add_column("Evidence", overflow="fold")

    for f in findings:
        sev_color = "red" if f.severity == "critical" else "yellow"
        row = [
            f.injection_point.param,
            f.technique,
            f.dbms or "unknown",
            f"[{sev_color}]{f.severity}[/{sev_color}]",
            f"{f.confidence:.2f}",
            "yes" if f.proven else "",
            f.evidence,
        ]
        if show_endpoint:
            row.insert(0, f.url)
        table.add_row(*row)
    console.print(table)

    console.print("\n[bold]Remediation[/bold]")
    seen = set()
    for f in findings:
        key = f.dbms or "generic"
        if key in seen:
            continue
        seen.add(key)
        console.print(f"  - [cyan]{key}[/cyan]: {remediation_for(f.dbms or '')}")


def to_sarif(findings: List[Finding], target: str) -> str:
    """Render findings as SARIF 2.1.0 for GitHub code scanning / CI ingestion.

    DAST findings don't map to source line numbers, so we use the target URL as the
    artifact location and put the parameter + technique in the message/properties.
    """
    # Deduplicate rules by technique.
    techniques = sorted({f.technique for f in findings})
    rules = [
        {
            "id": f"sqli/{tech}",
            "name": f"SQLInjection-{tech}",
            "shortDescription": {"text": f"SQL injection ({tech})"},
            "fullDescription": {
                "text": "User-controllable input reaches a SQL query without proper "
                "parameterization, allowing SQL injection."
            },
            "helpUri": "https://owasp.org/www-community/attacks/SQL_Injection",
            "properties": {"security-severity": "9.8", "tags": ["security", "sql-injection"]},
            "defaultConfiguration": {"level": "error"},
        }
        for tech in techniques
    ]

    results = []
    for f in findings:
        results.append(
            {
                "ruleId": f"sqli/{f.technique}",
                "level": "error",
                "message": {
                    "text": (
                        f"SQL injection in parameter '{f.injection_point.param}' "
                        f"({f.injection_point.location}) via {f.technique}; "
                        f"dbms={f.dbms or 'unknown'}, proven={f.proven}. "
                        f"{remediation_for(f.dbms or '')}"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            # Per-finding endpoint in crawl mode; falls back to the seed.
                            "artifactLocation": {"uri": f.url or target},
                        }
                    }
                ],
                "properties": {
                    "param": f.injection_point.param,
                    "technique": f.technique,
                    "confidence": f.confidence,
                    "proven": f.proven,
                    "payload": f.payload,
                },
            }
        )

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SQLintel",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/Mayankk-098/sqlintel",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


def to_json(findings: List[Finding], target: str) -> str:
    payload = {
        "tool": "SQLintel",
        "version": "0.1.0",
        "target": target,
        "summary": {
            "findings": len(findings),
            "proven": sum(1 for f in findings if f.proven),
        },
        "results": [
            {
                "url": f.url or target,
                "param": f.injection_point.param,
                "location": f.injection_point.location,
                "technique": f.technique,
                "dbms": f.dbms,
                "severity": f.severity,
                "confidence": f.confidence,
                "proven": f.proven,
                "payload": f.payload,
                "evidence": f.evidence,
                "remediation": remediation_for(f.dbms or ""),
            }
            for f in findings
        ],
    }
    return json.dumps(payload, indent=2)
