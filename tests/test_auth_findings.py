from src.auth_analyzer import build_auth_findings


def test_build_spf_failure_finding():
    findings = build_auth_findings({
        "spf": "fail",
        "dkim": "pass",
        "dmarc": "pass",
    })

    assert len(findings) == 1
    assert findings[0] == {
        "type": "SPF_FAIL",
        "severity": "MEDIUM",
        "description": "SPF authentication returned fail.",
        "evidence": "spf=fail",
        "score": 20,
    }


def test_build_dmarc_failure_finding():
    findings = build_auth_findings({
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "fail",
    })

    assert len(findings) == 1
    assert findings[0]["type"] == "DMARC_FAIL"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["score"] == 30


def test_unknown_results_do_not_create_findings():
    findings = build_auth_findings({
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown",
    })

    assert findings == []


def test_conflicting_authentication_creates_findings():
    findings = build_auth_findings({
        "spf": "conflict",
        "dkim": "pass",
        "dmarc": "conflict",
    })

    assert len(findings) == 2
    assert findings[0]["type"] == "SPF_CONFLICT"
    assert findings[1]["type"] == "DMARC_CONFLICT"
