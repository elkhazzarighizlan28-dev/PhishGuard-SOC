
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
