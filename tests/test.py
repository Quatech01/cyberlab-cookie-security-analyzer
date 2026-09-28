import json
import subprocess
import sys

import httpx
import pytest

sys.path.insert(0, "..")
from server.main import app, start  # noqa: E402

BASE_URL = None
_server = None


@pytest.fixture(scope="session", autouse=True)
def run_server():
    global BASE_URL, _server
    port = 3678
    BASE_URL = f"http://127.0.0.1:{port}"
    _server = start(port)
    yield
    _server.should_exit = True


def run_tool(target=None):
    """Run the scanner tool against the given target and return the parsed JSON result."""
    url = target if target is not None else BASE_URL
    result = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", url],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    return result, json.loads(result.stdout)


# ── Group 1: Server health ─────────────────────────────────────────────────────

class TestServerHealth:
    def test_health_returns_200(self):
        r = httpx.get(f"{BASE_URL}/health")
        assert r.status_code == 200

    def test_health_body_status_ok(self):
        r = httpx.get(f"{BASE_URL}/health")
        assert r.json()["status"] == "ok"

    def test_targets_returns_200(self):
        r = httpx.get(f"{BASE_URL}/targets")
        assert r.status_code == 200

    def test_targets_has_endpoints_key(self):
        r = httpx.get(f"{BASE_URL}/targets")
        data = r.json()
        assert "endpoints" in data

    def test_targets_lists_six_endpoints(self):
        r = httpx.get(f"{BASE_URL}/targets")
        assert len(r.json()["endpoints"]) == 6


# ── Group 2: True positives (vulnerable endpoints flagged) ────────────────────

class TestTruePositives:
    def test_bare_cookie_has_no_httponly(self):
        r = httpx.get(f"{BASE_URL}/set-cookie/bare")
        raw = r.headers.get("set-cookie", "")
        assert "httponly" not in raw.lower()

    def test_bare_cookie_has_no_secure(self):
        r = httpx.get(f"{BASE_URL}/set-cookie/bare")
        raw = r.headers.get("set-cookie", "")
        # Check directives only (after first semicolon) to avoid matching the cookie value
        directives = [d.strip().lower() for d in raw.split(";")[1:]]
        assert "secure" not in directives

    def test_bare_cookie_has_no_samesite(self):
        r = httpx.get(f"{BASE_URL}/set-cookie/bare")
        raw = r.headers.get("set-cookie", "")
        assert "samesite" not in raw.lower()

    def test_tool_flags_bare_endpoint(self):
        _, result = run_tool()
        endpoints_flagged = [f["endpoint"] for f in result["findings"]]
        assert "/set-cookie/bare" in endpoints_flagged

    def test_tool_reports_missing_httponly_on_bare(self):
        _, result = run_tool()
        bare_findings = [f for f in result["findings"] if f["endpoint"] == "/set-cookie/bare"]
        types = [f["vulnerability_type"] for f in bare_findings]
        assert "MISSING_HTTPONLY" in types

    def test_tool_reports_missing_secure_on_bare(self):
        _, result = run_tool()
        bare_findings = [f for f in result["findings"] if f["endpoint"] == "/set-cookie/bare"]
        types = [f["vulnerability_type"] for f in bare_findings]
        assert "MISSING_SECURE" in types

    def test_tool_reports_missing_samesite_on_bare(self):
        _, result = run_tool()
        bare_findings = [f for f in result["findings"] if f["endpoint"] == "/set-cookie/bare"]
        types = [f["vulnerability_type"] for f in bare_findings]
        assert "MISSING_SAMESITE" in types

    def test_tool_reports_missing_secure_on_httponly_only(self):
        _, result = run_tool()
        findings = [f for f in result["findings"] if f["endpoint"] == "/set-cookie/httponly-only"]
        types = [f["vulnerability_type"] for f in findings]
        assert "MISSING_SECURE" in types

    def test_tool_reports_missing_samesite_on_httponly_secure(self):
        _, result = run_tool()
        findings = [f for f in result["findings"] if f["endpoint"] == "/set-cookie/httponly-secure"]
        types = [f["vulnerability_type"] for f in findings]
        assert "MISSING_SAMESITE" in types

    def test_tool_reports_insecure_samesite_none(self):
        _, result = run_tool()
        findings = [f for f in result["findings"] if f["endpoint"] == "/set-cookie/none-no-secure"]
        types = [f["vulnerability_type"] for f in findings]
        assert "INSECURE_SAMESITE_NONE" in types

    def test_insecure_samesite_none_severity_is_high(self):
        _, result = run_tool()
        findings = [
            f for f in result["findings"]
            if f["endpoint"] == "/set-cookie/none-no-secure"
            and f["vulnerability_type"] == "INSECURE_SAMESITE_NONE"
        ]
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"

    def test_missing_httponly_severity_is_high(self):
        _, result = run_tool()
        findings = [
            f for f in result["findings"]
            if f["vulnerability_type"] == "MISSING_HTTPONLY"
        ]
        assert all(f["severity"] == "HIGH" for f in findings)

    def test_missing_secure_severity_is_high(self):
        _, result = run_tool()
        findings = [
            f for f in result["findings"]
            if f["vulnerability_type"] == "MISSING_SECURE"
        ]
        assert all(f["severity"] == "HIGH" for f in findings)

    def test_missing_samesite_severity_is_medium(self):
        _, result = run_tool()
        findings = [
            f for f in result["findings"]
            if f["vulnerability_type"] == "MISSING_SAMESITE"
        ]
        assert all(f["severity"] == "MEDIUM" for f in findings)


# ── Group 3: False positives (safe endpoints not flagged) ─────────────────────

class TestFalsePositives:
    def test_full_secure_cookie_has_httponly(self):
        r = httpx.get(f"{BASE_URL}/set-cookie/full-secure")
        raw = r.headers.get("set-cookie", "")
        assert "httponly" in raw.lower()

    def test_full_secure_cookie_has_secure(self):
        r = httpx.get(f"{BASE_URL}/set-cookie/full-secure")
        raw = r.headers.get("set-cookie", "")
        assert "secure" in raw.lower()

    def test_full_secure_cookie_has_samesite_strict(self):
        r = httpx.get(f"{BASE_URL}/set-cookie/full-secure")
        raw = r.headers.get("set-cookie", "")
        assert "samesite=strict" in raw.lower()

    def test_tool_does_not_flag_full_secure(self):
        _, result = run_tool()
        endpoints_flagged = {f["endpoint"] for f in result["findings"]}
        assert "/set-cookie/full-secure" not in endpoints_flagged

    def test_tool_does_not_flag_samesite_lax(self):
        _, result = run_tool()
        endpoints_flagged = {f["endpoint"] for f in result["findings"]}
        assert "/set-cookie/samesite-lax" not in endpoints_flagged

    def test_samesite_lax_cookie_flags_present(self):
        r = httpx.get(f"{BASE_URL}/set-cookie/samesite-lax")
        raw = r.headers.get("set-cookie", "").lower()
        assert "httponly" in raw
        assert "secure" in raw
        assert "samesite=lax" in raw


# ── Group 4: Output format ────────────────────────────────────────────────────

class TestOutputFormat:
    def test_tool_exits_zero(self):
        proc, _ = run_tool()
        assert proc.returncode == 0

    def test_output_is_valid_json(self):
        proc, _ = run_tool()  # json.loads raises on invalid JSON
        assert proc.returncode == 0

    def test_output_has_target_field(self):
        _, result = run_tool()
        assert "target" in result

    def test_target_field_matches_input(self):
        _, result = run_tool()
        assert BASE_URL in result["target"]

    def test_output_has_findings_list(self):
        _, result = run_tool()
        assert "findings" in result
        assert isinstance(result["findings"], list)

    def test_output_has_summary_string(self):
        _, result = run_tool()
        assert "summary" in result
        assert isinstance(result["summary"], str)
        assert len(result["summary"]) > 0

    def test_each_finding_has_endpoint(self):
        _, result = run_tool()
        for f in result["findings"]:
            assert "endpoint" in f

    def test_each_finding_has_vulnerability_type(self):
        _, result = run_tool()
        for f in result["findings"]:
            assert "vulnerability_type" in f

    def test_each_finding_has_evidence(self):
        _, result = run_tool()
        for f in result["findings"]:
            assert "evidence" in f
            assert len(f["evidence"]) > 0

    def test_each_finding_has_severity(self):
        _, result = run_tool()
        for f in result["findings"]:
            assert "severity" in f

    def test_severity_values_are_valid(self):
        _, result = run_tool()
        valid = {"HIGH", "MEDIUM", "LOW", "INFO"}
        for f in result["findings"]:
            assert f["severity"] in valid

    def test_total_findings_count_correct(self):
        _, result = run_tool()
        # bare: 3 findings, httponly-only: 2 findings, httponly-secure: 1 finding,
        # none-no-secure: 1 finding  →  total ≥ 7
        assert len(result["findings"]) >= 7


# ── Group 5: Edge cases ───────────────────────────────────────────────────────

class TestEdgeCases:
    def test_unreachable_target_returns_empty_findings(self):
        _, result = run_tool(target="http://127.0.0.1:19999")
        assert result["findings"] == []

    def test_unreachable_target_exit_code_zero(self):
        proc, _ = run_tool(target="http://127.0.0.1:19999")
        assert proc.returncode == 0

    def test_unreachable_target_has_summary(self):
        _, result = run_tool(target="http://127.0.0.1:19999")
        assert "summary" in result
        assert len(result["summary"]) > 0

    def test_endpoint_with_no_set_cookie_header(self):
        r = httpx.get(f"{BASE_URL}/health")
        assert r.headers.get("set-cookie") is None

    def test_all_flagged_endpoints_have_evidence_text(self):
        _, result = run_tool()
        for f in result["findings"]:
            assert isinstance(f["evidence"], str)
            assert len(f["evidence"]) > 20
