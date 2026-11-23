from src.detection_engine import (
    analyze_reply_to,
    analyze_urls,
    analyze_urgency,
)
from src.schemas import Finding


def test_reply_to_returns_finding_object():
    email = {
        "from": "support@example.com",
        "reply_to": "attacker@evil.com",
    }

    result = analyze_reply_to(email)

    assert isinstance(result, Finding)
    assert result.type == "REPLY_TO_MISMATCH"


def test_urls_return_finding_objects():
    findings = analyze_urls(
        "Visit http://example.com/login"
    )

    assert len(findings) == 1
    assert all(isinstance(item, Finding) for item in findings)
    assert findings[0].type == "INSECURE_HTTP"


def test_urgency_returns_finding_object():
    result = analyze_urgency(
        "Verify your account immediately"
    )

    assert isinstance(result, Finding)
    assert result.type == "URGENCY_LANGUAGE"


def test_no_urgency_returns_none():
    result = analyze_urgency(
        "Hello, here is your requested document."
    )

    assert result is None
