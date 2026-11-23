from src.domain_analyzer import (
    SIMILARITY_THRESHOLD,
    analyze_domain_similarity,
    calculate_similarity,
)


def test_detect_paypal_typosquatting():
    email = {"from": "support@paypa1.com"}

    finding = analyze_domain_similarity(email)

    assert finding is not None
    assert finding.type == "DOMAIN_SIMILARITY"
    assert finding.severity == "HIGH"
    assert finding.score == 30
    assert "paypal.com" in finding.evidence


def test_detect_microsoft_typosquatting():
    email = {"from": "support@micros0ft.com"}

    finding = analyze_domain_similarity(email)

    assert finding is not None
    assert finding.type == "DOMAIN_SIMILARITY"


def test_detect_google_typosquatting():
    email = {"from": "support@g00gle.com"}

    finding = analyze_domain_similarity(email)

    assert finding is not None
    assert finding.type == "DOMAIN_SIMILARITY"


def test_official_domain_is_not_flagged():
    email = {"from": "support@paypal.com"}

    assert analyze_domain_similarity(email) is None


def test_official_subdomain_is_not_flagged():
    email = {"from": "support@login.paypal.com"}

    assert analyze_domain_similarity(email) is None


def test_unrelated_domain_is_not_flagged():
    email = {"from": "user@example.com"}

    assert analyze_domain_similarity(email) is None


def test_missing_sender_is_not_flagged():
    assert analyze_domain_similarity({}) is None


def test_similarity_calculation():
    assert calculate_similarity("paypal", "paypa1") == 1.0
    assert calculate_similarity("microsoft", "micros0ft") == 1.0
    assert calculate_similarity("google", "g00gle") == 1.0
    assert calculate_similarity("paypal", "paypal") == 1.0


def test_unrelated_domain_similarity_is_below_threshold():
    similarity = calculate_similarity("example", "apple")

    assert similarity < SIMILARITY_THRESHOLD
