
from src.detection_engine import analyze_email, extract_urls


def test_extract_urls():
    text = "Visit http://example.com/login"
    urls = extract_urls(text)

    assert len(urls) == 1
    assert urls[0] == "http://example.com/login"


def test_reply_to_mismatch():
    email = {
        "from": "support@example.com",
        "reply_to": "attacker@evil.com",
        "subject": "Hello",
        "body": "Normal message",
    }

    result = analyze_email(email)

    assert any(
        f["type"] == "REPLY_TO_MISMATCH"
        for f in result["findings"]
    )


def test_urgency_detection():
    email = {
        "from": "user@example.com",
        "reply_to": "",
        "subject": "Urgent action required",
        "body": "Verify your account immediately",
    }

    result = analyze_email(email)

    assert any(
        f["type"] == "URGENCY_LANGUAGE"
        for f in result["findings"]
    )


def test_http_detection():
    email = {
        "from": "user@example.com",
        "reply_to": "",
        "subject": "Hello",
        "body": "Visit http://example.com/login",
    }

    result = analyze_email(email)

    assert any(
        f["type"] == "INSECURE_HTTP"
        for f in result["findings"]
    )


def test_risk_score_range():
    email = {
        "from": "support@example.com",
        "reply_to": "attacker@evil.com",
        "subject": "Urgent",
        "body": "Verify immediately at http://example.com",
    }

    result = analyze_email(email)

    assert 0 <= result["risk_score"] <= 100
    assert result["risk_level"] in [
        "LOW", "MEDIUM", "HIGH", "CRITICAL"
    ]
def test_spf_failure_creates_finding():
    email = {
        "from": "attacker@example.com",
        "reply_to": "",
        "subject": "Hello",
        "body": "Normal message",
        "authentication_results": [
            "mx.example.com; spf=fail"
        ],
    }

    result = analyze_email(email)

    assert any(
        finding["type"] == "SPF_FAIL"
        for finding in result["findings"]
    )


def test_dmarc_failure_increases_risk_score():
    email = {
        "from": "attacker@example.com",
        "reply_to": "",
        "subject": "Hello",
        "body": "Normal message",
        "authentication_results": [
            "mx.example.com; dmarc=fail"
        ],
    }

    result = analyze_email(email)

    assert result["risk_score"] == 30
    assert result["risk_level"] == "MEDIUM"


def test_reply_to_same_address_with_display_names_is_not_mismatch():
    email = {
        "from": "Support Team <support@example.com>",
        "reply_to": "Support <support@example.com>",
        "subject": "Hello",
        "body": "Normal message",
        "authentication_results": [],
    }

    result = analyze_email(email)

    assert not any(
        finding["type"] == "REPLY_TO_MISMATCH"
        for finding in result["findings"]
    )


def test_reply_to_different_addresses_is_mismatch():
    email = {
        "from": "Support <support@example.com>",
        "reply_to": "Attacker <attacker@evil.com>",
        "subject": "Hello",
        "body": "Normal message",
        "authentication_results": [],
    }

    result = analyze_email(email)

    assert any(
        finding["type"] == "REPLY_TO_MISMATCH"
        for finding in result["findings"]
    )
