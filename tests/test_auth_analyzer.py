
from src.auth_analyzer import analyze_authentication


def test_all_authentication_methods_pass():
    headers = [
        "mx.example.com; spf=pass; dkim=pass; dmarc=pass"
    ]

    result = analyze_authentication(headers)

    assert result == {
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass",
    }


def test_authentication_failures():
    headers = [
        "mx.example.com; spf=fail; dkim=fail; dmarc=fail"
    ]

    result = analyze_authentication(headers)

    assert result["spf"] == "fail"
    assert result["dkim"] == "fail"
    assert result["dmarc"] == "fail"


def test_missing_authentication_results():
    result = analyze_authentication([])

    assert result == {
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown",
    }


def test_conflicting_results():
    headers = [
        "mx.example.com; spf=pass",
        "mx.example.com; spf=fail",
    ]

    result = analyze_authentication(headers)

    assert result["spf"] == "conflict"


def test_untrusted_input_type_is_ignored():
    result = analyze_authentication(None)

    assert result["spf"] == "unknown"
    assert result["dkim"] == "unknown"
    assert result["dmarc"] == "unknown"


def test_invalid_status_is_ignored():
    headers = [
        "mx.example.com; spf=something_invalid; dkim=pass"
    ]

    result = analyze_authentication(headers)

    assert result["spf"] == "unknown"
    assert result["dkim"] == "pass"


def test_does_not_match_fake_method_names():
    headers = [
        "mx.example.com; x-spf=pass; dkim=pass"
    ]

    result = analyze_authentication(headers)

    assert result["spf"] == "unknown"
    assert result["dkim"] == "pass"
