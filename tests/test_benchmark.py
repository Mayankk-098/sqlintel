"""Unit tests for the benchmark metric math and the sqlmap/Ghauri stdout parsers.

These are pure/offline: no mock server, no sqlmap, no Ghauri — so CI stays green on a
machine with only SQLintel installed.
"""

import math

from benchmark.harness import (
    confusion,
    detect_tools,
    ghauri_cmd,
    metrics_from_counts,
    parse_ghauri_output,
    parse_sqlmap_output,
    render_table,
    sqlintel_cmd,
    sqlmap_cmd,
)
from benchmark.targets import DVWA_TARGETS, MOCK_TARGETS


def _target(body_kind):
    return next(t for t in MOCK_TARGETS if t.body_kind == body_kind)


# --- metric math -----------------------------------------------------------------------

def test_confusion_counts_from_pairs():
    # (found, vulnerable): 1 TP, 1 FP, 1 TN, 1 FN
    pairs = [(True, True), (True, False), (False, False), (False, True)]
    assert confusion(pairs) == (1, 1, 1, 1)


def test_metrics_from_counts_perfect_classifier():
    m = metrics_from_counts(tp=2, fp=0, tn=2, fn=0, mean_time=1.5)
    assert m.precision == 1.0
    assert m.recall == 1.0
    assert m.f1 == 1.0
    assert m.fp_rate == 0.0
    assert m.accuracy == 1.0
    assert m.mean_time == 1.5


def test_metrics_flag_everything_has_high_fp_rate():
    # A scanner that flags everything: perfect recall, terrible FP-rate + precision.
    m = metrics_from_counts(tp=2, fp=2, tn=0, fn=0)
    assert m.recall == 1.0
    assert m.fp_rate == 1.0          # every true-negative was misfired on
    assert m.precision == 0.5
    assert math.isclose(m.f1, 2 / 3, rel_tol=1e-9)
    assert m.accuracy == 0.5


def test_metrics_mixed_case():
    m = metrics_from_counts(tp=3, fp=1, tn=4, fn=2)
    assert math.isclose(m.precision, 3 / 4)
    assert math.isclose(m.recall, 3 / 5)
    assert math.isclose(m.fp_rate, 1 / 5)
    assert math.isclose(m.accuracy, 7 / 10)


def test_metrics_no_division_by_zero_on_empty():
    m = metrics_from_counts(0, 0, 0, 0)
    assert (m.precision, m.recall, m.f1, m.fp_rate, m.accuracy) == (0.0, 0.0, 0.0, 0.0, 0.0)


# --- stdout parsers --------------------------------------------------------------------

_SQLMAP_VULN = """
sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:
---
Parameter: id (GET)
    Type: error-based
"""
_SQLMAP_CLEAN = (
    "[CRITICAL] all tested parameters do not appear to be injectable. Try to increase "
    "values for '--level'/'--risk' options"
)

_GHAURI_VULN = "[+] Parameter: 'id' is vulnerable. Do you want to keep testing? [y/N]"
_GHAURI_CLEAN = "[-] the parameter 'id' does not seem to be injectable"


def test_sqlmap_parser_detects_vulnerable():
    assert parse_sqlmap_output(_SQLMAP_VULN) is True


def test_sqlmap_parser_ignores_clean_run():
    # "injectable" appears in the negative phrasing too — the parser must not trip on it.
    assert parse_sqlmap_output(_SQLMAP_CLEAN) is False


def test_ghauri_parser_detects_vulnerable():
    assert parse_ghauri_output(_GHAURI_VULN) is True


def test_ghauri_parser_ignores_clean_run():
    assert parse_ghauri_output(_GHAURI_CLEAN) is False


# --- misc plumbing ---------------------------------------------------------------------

def test_detect_tools_sqlintel_always_available():
    available, skipped = detect_tools(["sqlintel", "definitely-not-a-real-tool-xyz"])
    assert "sqlintel" in available
    assert "definitely-not-a-real-tool-xyz" in skipped


def test_mock_targets_have_both_labels():
    # FP-rate is only measurable with true negatives present.
    labels = {t.vulnerable for t in MOCK_TARGETS}
    assert labels == {True, False}
    assert any(t.body_kind == "json" for t in MOCK_TARGETS)  # SQLintel's differentiator


def test_render_table_is_ascii_only():
    results = [{"tool": "sqlintel",
                "metrics": metrics_from_counts(2, 0, 2, 0, 0.1).__dict__}]
    table = render_table(results)
    assert table.isascii()          # must survive Windows cp1252
    assert "sqlintel" in table


# --- command builders ------------------------------------------------------------------

def test_sqlintel_cmd_json_target_uses_json_body():
    cmd = sqlintel_cmd("http://h", _target("json"))
    assert "--json-body" in cmd
    assert "-d" in cmd                                  # JSON body is passed via -d
    assert "http://h/api/item" in cmd


def test_sqlintel_cmd_query_target_has_no_body_flags():
    cmd = sqlintel_cmd("http://h", _target("query"))
    assert "--json-body" not in cmd
    assert "-d" not in cmd


def test_sqlmap_and_ghauri_send_json_body_as_data():
    t = _target("json")
    assert "--data" in sqlmap_cmd("http://h", t)
    assert '{"id": 1}' in sqlmap_cmd("http://h", t)
    assert "--data" in ghauri_cmd("http://h", t)


def test_cookie_threaded_into_every_tool():
    t = DVWA_TARGETS[0]
    cookie = "PHPSESSID=deadbeef; security=low"
    # SQLintel takes it as a Cookie header, sqlmap/Ghauri via --cookie.
    assert f"Cookie: {cookie}" in sqlintel_cmd("http://h", t, cookie)
    for builder in (sqlmap_cmd, ghauri_cmd):
        cmd = builder("http://h", t, cookie)
        assert "--cookie" in cmd
        assert cookie in cmd


def test_no_cookie_means_no_auth_flags():
    t = MOCK_TARGETS[0]
    assert "--cookie" not in sqlmap_cmd("http://h", t)
    assert "-H" not in sqlintel_cmd("http://h", t)
