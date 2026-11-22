from src.sender_analyzer import analyze_sender_identity


def test_detect_paypal_display_name_impersonation():
    email = {
        "from": "PayPal Support <attacker@evil.com>"
    }

    finding = analyze_sender_identity(email)

    assert finding is not None
    assert finding.type == "DISPLAY_NAME_BRAND_IMPERSONATION"
    assert finding.severity == "HIGH"
    assert finding.score == 30
    assert "evil.com" in finding.evidence


def test_detect_microsoft_display_name_impersonation():
    email = {
        "from": "Microsoft Security <security@fake-domain.com>"
    }

    finding = analyze_sender_identity(email)

    assert finding is not None
    assert finding.type == "DISPLAY_NAME_BRAND_IMPERSONATION"


def test_official_brand_domain_is_not_flagged():
    email = {
        "from": "PayPal Support <support@paypal.com>"
    }

    assert analyze_sender_identity(email) is None


def test_official_brand_subdomain_is_not_flagged():
    email = {
        "from": "Google Support <support@accounts.google.com>"
    }

    assert analyze_sender_identity(email) is None


def test_unrelated_display_name_is_not_flagged():
    email = {
        "from": "Support Team <support@example.com>"
    }

    assert analyze_sender_identity(email) is None


def test_missing_sender_is_not_flagged():
    assert analyze_sender_identity({}) is None


def test_brand_in_email_address_without_display_name_is_not_flagged():
    email = {
        "from": "paypal@evil.com"
    }

    assert analyze_sender_identity(email) is None
