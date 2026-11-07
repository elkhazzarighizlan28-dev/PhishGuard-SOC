
from src.email_parser import parse_email


def test_parse_suspicious_email():
    email = parse_email(
        "samples/suspicious_email.eml"
    )

    assert email["from"] == "support@paypa1.example"
    assert email["reply_to"] == "attacker@evil.example"
    assert "Urgent" in email["subject"]
    assert "verify" in email["body"].lower()
