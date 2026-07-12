"""Offline unit tests — no network required."""

from sqlintel.cli import _apply_json_body, build_parser
from sqlintel.core.request_parser import from_url
from sqlintel.ml.features import finding_features, payload_features
from sqlintel.payloads.data import all_time_payloads, match_dbms_error
from sqlintel.report.reporter import remediation_for, to_json, to_sarif
from sqlintel.core.target import Finding, InjectionPoint, Request
from sqlintel.core.http_client import Response
from sqlintel.verify.proof import ProofVerifier


def test_from_url_parses_query_params():
    req = from_url("http://host/item?id=1&cat=books")
    assert req.method == "GET"
    assert req.query == {"id": "1", "cat": "books"}
    points = {p.param for p in req.injection_points()}
    assert points == {"id", "cat"}


def test_from_url_with_data_becomes_post():
    req = from_url("http://host/login", method="GET", data="user=admin&pass=x")
    assert req.method == "POST"
    assert req.body == {"user": "admin", "pass": "x"}


def test_json_body_flag_builds_json_request():
    # --json-body: -d is a JSON object, so from_url gets no form data and we load it
    # via _apply_json_body -> scalar fields become string injection points on a JSON body.
    req = from_url("http://host/api/item", method="GET", data="")
    _apply_json_body(req, '{"id": 1, "q": "shoes", "meta": {"nested": true}}')
    assert req.body_type == "json"
    assert req.method == "POST"
    assert req.body == {"id": "1", "q": "shoes"}  # nested object dropped from fuzz set
    assert {p.param for p in req.injection_points()} == {"id", "q"}


def test_json_body_flag_is_registered():
    args = build_parser().parse_args(["-u", "http://h/api", "-d", "{}", "--json-body"])
    assert args.json_body is True


def test_param_filter():
    req = from_url("http://host/i?a=1&b=2&c=3")
    only = [p.param for p in req.injection_points(only=["a", "c"])]
    assert set(only) == {"a", "c"}


def test_match_dbms_error_detects_mysql():
    text = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
    dbms, snippet = match_dbms_error(text)
    assert dbms == "MySQL"
    assert snippet


def test_no_false_error_match_on_clean_text():
    dbms, _ = match_dbms_error("<html><body>Welcome, user 1</body></html>")
    assert dbms == ""


def test_time_payloads_substitute_delay():
    payloads = all_time_payloads(7)
    assert any("SLEEP(7)" in p for _dbms, p in payloads)
    assert all("{delay}" not in p for _dbms, p in payloads)


def test_features_are_numeric():
    feats = finding_features("time-based", 0.85, "' AND SLEEP(5)-- -")
    assert feats["tech_time-based"] == 1.0
    assert feats["det_confidence"] == 0.85
    assert all(isinstance(v, float) for v in feats.values())
    assert payload_features("' OR 1=1-- -")["has_comment"] == 1.0


def test_json_report_shape():
    f = Finding(
        injection_point=InjectionPoint(param="id", value="1"),
        technique="error-based",
        dbms="MySQL",
        payload="'",
        evidence="SQL syntax ... MySQL",
        confidence=0.9,
    )
    import json

    report = json.loads(to_json([f], "http://host/i?id=1"))
    assert report["summary"]["findings"] == 1
    assert report["results"][0]["param"] == "id"
    assert "parameterized" in report["results"][0]["remediation"].lower()


def test_remediation_includes_generic_advice():
    assert "prepared statements" in remediation_for("MySQL").lower()


def test_sarif_report_is_valid_shape():
    import json

    f = Finding(
        injection_point=InjectionPoint(param="id", value="1"),
        technique="error-based",
        dbms="MySQL",
        payload="'",
        proven=True,
    )
    doc = json.loads(to_sarif([f], "http://host/i?id=1"))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "SQLintel"
    assert run["results"][0]["ruleId"] == "sqli/error-based"
    assert run["results"][0]["level"] == "error"


class _StubClient:
    """Fake HTTP client for proof tests: error on odd quotes, else baseline text."""

    ERROR = "check the manual that corresponds to your MySQL server version"

    def send(self, req, mutation=None):
        val = list(mutation.values())[0] if mutation else ""
        if val.count("'") % 2 == 1:  # unbalanced quote -> DB error
            return Response(200, f"<html>{self.ERROR}</html>", 0.01, {})
        return Response(200, "<html>baseline product page</html>", 0.01, {})


def test_response_ok_reflects_error():
    assert Response(200, "ok", 0.01, {}).ok is True
    assert Response(0, "", 0.0, {}, error="boom").ok is False


def test_http_client_send_survives_network_error(monkeypatch):
    import httpx

    from sqlintel.core.http_client import HttpClient

    client = HttpClient()

    def boom(*_a, **_k):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(client._client, "request", boom)
    resp = client.send(Request(method="GET", url="http://host/i", query={"id": "1"}))
    client.close()
    assert resp.ok is False
    assert resp.error
    assert resp.elapsed == 0.0          # must never look like a time-based delay


def test_engine_skips_target_on_failed_baseline():
    from sqlintel.core.engine import Engine

    class FailBaseline:
        def baseline(self, req):
            return Response(0, "", 0.0, {}, error="reset")

        def send(self, req, mutation=None):
            return Response(0, "", 0.0, {}, error="reset")

    findings = Engine(FailBaseline(), verify=False).scan(
        Request(method="GET", url="http://h/i", query={"id": "1"})
    )
    assert findings == []


def test_time_based_ignores_failed_control():
    from sqlintel.detectors.time_based import TimeBasedDetector

    baseline = Response(200, "ok", 0.01, {})

    class Client:
        def send(self, req, mutation=None):
            val = list(mutation.values())[0].lower()
            is_sleep = "sleep" in val or "waitfor" in val
            is_control = "(0)" in val or "0:0:0" in val
            if is_sleep and is_control:
                return Response(0, "", 0.0, {}, error="reset")   # control fails
            if is_sleep:
                return Response(200, "ok", 9.0, {})              # real-looking delay
            return baseline

    finding = TimeBasedDetector(Client(), baseline, delay=5).test(
        Request(method="GET", url="http://h", query={"id": "1"}),
        InjectionPoint(param="id", value="1"),
    )
    assert finding is None   # a network error on the control must not confirm a delay


def test_error_proof_sets_proven():
    baseline = Response(200, "<html>baseline product page</html>", 0.01, {})
    req = Request(method="GET", url="http://host/i", query={"id": "1"})
    finding = Finding(
        injection_point=InjectionPoint(param="id", value="1"),
        technique="error-based",
        dbms="MySQL",
        payload="'",
    )
    ProofVerifier(_StubClient(), baseline).verify(req, finding)
    assert finding.proven is True
    assert "PROVEN" in finding.evidence
