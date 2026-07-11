"""Benchmark harness: run each tool against labeled targets, score honest metrics.

Adapters (`run_sqlintel` / `run_sqlmap` / `run_ghauri`) each return
``(found: bool, elapsed: float, raw: str)``. External tools are auto-detected with
``shutil.which`` and skipped gracefully when absent, so the benchmark still runs (and CI
stays green) on a machine that only has SQLintel installed.

We deliberately measure precision, recall, F1, **false-positive rate**, and accuracy —
not just recall — which is why the target manifest includes SAFE endpoints as true
negatives. A scanner that flags everything gets perfect recall and is useless; only the
full confusion matrix shows that.

Console output is ASCII-only (Windows cp1252 can't encode box-drawing/arrows).
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from typing import Callable, Dict, List, Optional, Tuple

from .targets import Target

# SQLintel signals findings through its exit code (see cli.main): 1 = findings, 0 = none.
SQLINTEL_FOUND_EXIT = 1

# Marker substrings chosen so they appear in a tool's *positive* output but NOT in its
# "nothing found" output — verified by tests/test_benchmark.py against sample strings.
_SQLMAP_POSITIVE = ("following injection point", "is vulnerable")
_GHAURI_POSITIVE = ("is vulnerable", "following injection point")


def parse_sqlmap_output(out: str) -> bool:
    """True if sqlmap's stdout reports at least one injection point."""
    low = out.lower()
    return any(marker in low for marker in _SQLMAP_POSITIVE)


def parse_ghauri_output(out: str) -> bool:
    """True if Ghauri's stdout reports a vulnerable/injectable parameter."""
    low = out.lower()
    return any(marker in low for marker in _GHAURI_POSITIVE)


def _run_command(cmd: List[str], timeout: float) -> Tuple[int, float, str]:
    """Run `cmd`, capturing combined stdout+stderr. Returns (returncode, elapsed, raw).

    A timeout is reported as returncode -1 with whatever output was captured so far — the
    caller's stdout parser then simply sees no success marker (a miss), which is correct.
    """
    start = time.perf_counter()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        code, out, err = proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        code = -1
        out = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
    except FileNotFoundError:
        code, out, err = -1, "", "tool not found on PATH"
    elapsed = time.perf_counter() - start
    return code, elapsed, (out + err)


def run_sqlintel(base_url: str, t: Target, timeout: float) -> Tuple[bool, float, str]:
    """Adapter for SQLintel itself — the current Python interpreter, always available."""
    cmd = [sys.executable, "-m", "sqlintel", "-u", base_url + t.path,
           "-p", t.param, "--batch", "-q"]
    if t.body_kind == "json":
        cmd += ["-d", t.data or "{}", "--json-body"]
    elif t.body_kind == "form":
        cmd += ["-d", t.data or ""]
    code, elapsed, raw = _run_command(cmd, timeout)
    return code == SQLINTEL_FOUND_EXIT, elapsed, raw


def run_sqlmap(base_url: str, t: Target, timeout: float) -> Tuple[bool, float, str]:
    exe = shutil.which("sqlmap")
    cmd = [exe or "sqlmap", "-u", base_url + t.path, "-p", t.param,
           "--batch", "--flush-session", "--level=1", "--risk=1"]
    if t.body_kind in ("form", "json") and t.data:
        cmd += ["--data", t.data]  # sqlmap auto-detects a JSON body and tests its params
    _code, elapsed, raw = _run_command(cmd, timeout)
    return parse_sqlmap_output(raw), elapsed, raw


def run_ghauri(base_url: str, t: Target, timeout: float) -> Tuple[bool, float, str]:
    exe = shutil.which("ghauri")
    cmd = [exe or "ghauri", "-u", base_url + t.path, "-p", t.param, "--batch"]
    if t.body_kind in ("form", "json") and t.data:
        cmd += ["--data", t.data]
    _code, elapsed, raw = _run_command(cmd, timeout)
    return parse_ghauri_output(raw), elapsed, raw


ADAPTERS: Dict[str, Callable[[str, Target, float], Tuple[bool, float, str]]] = {
    "sqlintel": run_sqlintel,
    "sqlmap": run_sqlmap,
    "ghauri": run_ghauri,
}


def detect_tools(requested: List[str]) -> Tuple[List[str], List[str]]:
    """Split `requested` into (available, skipped). SQLintel is always available."""
    available, skipped = [], []
    for name in requested:
        if name == "sqlintel" or shutil.which(name):
            available.append(name)
        else:
            skipped.append(name)
    return available, skipped


# --- Metrics ---------------------------------------------------------------------------

@dataclass
class Metrics:
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1: float
    fp_rate: float
    accuracy: float
    mean_time: float


def confusion(pairs: List[Tuple[bool, bool]]) -> Tuple[int, int, int, int]:
    """Count (tp, fp, tn, fn) from (found, vulnerable) pairs."""
    tp = sum(1 for found, vuln in pairs if found and vuln)
    fp = sum(1 for found, vuln in pairs if found and not vuln)
    tn = sum(1 for found, vuln in pairs if not found and not vuln)
    fn = sum(1 for found, vuln in pairs if not found and vuln)
    return tp, fp, tn, fn


def metrics_from_counts(tp: int, fp: int, tn: int, fn: int, mean_time: float = 0.0) -> Metrics:
    """Derive precision/recall/F1/FP-rate/accuracy from a confusion matrix.

    Split out from the run loop so it can be unit-tested with synthetic counts.
    """
    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fp_rate = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy = (tp + tn) / total if total else 0.0
    return Metrics(tp, fp, tn, fn, precision, recall, f1, fp_rate, accuracy, mean_time)


# --- Run loop + rendering --------------------------------------------------------------

def run_tool(name: str, base_url: str, targets: List[Target], timeout: float,
             on_event: Optional[Callable[[str], None]] = None) -> dict:
    """Run one tool across every target; return per-target rows + aggregate metrics."""
    adapter = ADAPTERS[name]
    emit = on_event or (lambda _msg: None)
    rows, pairs, times = [], [], []
    for t in targets:
        found, elapsed, _raw = adapter(base_url, t, timeout)
        correct = found == t.vulnerable
        emit(f"  {name:9s} {t.id:18s} found={str(found):5s} "
             f"truth={str(t.vulnerable):5s} {'ok' if correct else 'MISS'} {elapsed:.2f}s")
        rows.append({"target": t.id, "vulnerable": t.vulnerable,
                     "found": found, "correct": correct, "seconds": round(elapsed, 3)})
        pairs.append((found, t.vulnerable))
        times.append(elapsed)
    tp, fp, tn, fn = confusion(pairs)
    mean_time = sum(times) / len(times) if times else 0.0
    metrics = metrics_from_counts(tp, fp, tn, fn, mean_time)
    return {"tool": name, "rows": rows, "metrics": asdict(metrics)}


_COLS = ("tool", "TP", "FP", "TN", "FN", "prec", "recall", "F1", "FP-rate", "acc", "mean(s)")


def _fmt_row(name: str, m: dict) -> Tuple[str, ...]:
    return (
        name, str(m["tp"]), str(m["fp"]), str(m["tn"]), str(m["fn"]),
        f"{m['precision']:.2f}", f"{m['recall']:.2f}", f"{m['f1']:.2f}",
        f"{m['fp_rate']:.2f}", f"{m['accuracy']:.2f}", f"{m['mean_time']:.2f}",
    )


def render_table(results: List[dict]) -> str:
    """Render the aggregate metrics as a pure-ASCII table (safe on Windows cp1252)."""
    data = [_fmt_row(r["tool"], r["metrics"]) for r in results]
    widths = [max(len(_COLS[i]), *(len(row[i]) for row in data)) if data else len(_COLS[i])
              for i in range(len(_COLS))]
    sep = "+".join("-" * (w + 2) for w in widths)
    sep = f"+{sep}+"

    def line(cells: Tuple[str, ...]) -> str:
        return "| " + " | ".join(c.ljust(widths[i]) for i, c in enumerate(cells)) + " |"

    out = [sep, line(_COLS), sep]
    out += [line(row) for row in data]
    out.append(sep)
    return "\n".join(out)


def render_markdown(results: List[dict], base_url: str, target_set: str,
                    skipped: List[str]) -> str:
    """Render results.md: a methodology note, the metrics table, and per-target detail."""
    header = [
        "# SQLintel benchmark results",
        "",
        f"- Target set: `{target_set}`  ({base_url})",
        f"- Tools compared: {', '.join(r['tool'] for r in results) or 'none'}",
    ]
    if skipped:
        header.append(f"- Skipped (not installed): {', '.join(skipped)}")
    header += [
        "",
        "Metrics include the false-positive rate, measured against SAFE (non-vulnerable)",
        "endpoints as true negatives. Recall alone is not enough: a scanner that flags",
        "everything has perfect recall and a useless FP-rate.",
        "",
        "See benchmark/README.md for methodology and per-tool interpretation (e.g. why",
        "sqlmap declines to confirm on the blind mock oracle despite detecting it).",
        "",
        "## Aggregate metrics",
        "",
        "| " + " | ".join(_COLS) + " |",
        "|" + "|".join("---" for _ in _COLS) + "|",
    ]
    for r in results:
        header.append("| " + " | ".join(_fmt_row(r["tool"], r["metrics"])) + " |")

    header += ["", "## Per-target detail", ""]
    for r in results:
        header.append(f"### {r['tool']}")
        header.append("")
        header.append("| target | vulnerable | found | correct | seconds |")
        header.append("|---|---|---|---|---|")
        for row in r["rows"]:
            header.append(
                f"| {row['target']} | {row['vulnerable']} | {row['found']} "
                f"| {row['correct']} | {row['seconds']} |")
        header.append("")
    return "\n".join(header)
