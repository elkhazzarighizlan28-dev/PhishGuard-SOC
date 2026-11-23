import pytest

from src.schemas import Finding


def test_create_valid_finding():
    finding = Finding(
        type="REPLY_TO_MISMATCH",
        severity="MEDIUM",
        description="Reply-To differs from sender.",
        evidence="support@example.com -> attacker@evil.com",
        score=25,
    )

    assert finding.type == "REPLY_TO_MISMATCH"
    assert finding.severity == "MEDIUM"
    assert finding.score == 25


def test_convert_finding_to_legacy_dictionary():
    finding = Finding(
        type="INSECURE_HTTP",
        severity="LOW",
        description="URL uses HTTP.",
        evidence="http://example.com",
        score=10,
    )

    assert finding.to_dict() == {
        "type": "INSECURE_HTTP",
        "severity": "LOW",
        "description": "URL uses HTTP.",
        "evidence": "http://example.com",
        "score": 10,
    }


def test_reject_empty_type():
    with pytest.raises(ValueError):
        Finding("", "LOW", "Description", "Evidence", 10)


def test_reject_invalid_severity():
    with pytest.raises(ValueError):
        Finding("TEST", "INFO", "Description", "Evidence", 10)


def test_reject_score_above_100():
    with pytest.raises(ValueError):
        Finding("TEST", "HIGH", "Description", "Evidence", 101)


def test_reject_negative_score():
    with pytest.raises(ValueError):
        Finding("TEST", "LOW", "Description", "Evidence", -1)


def test_reject_boolean_score():
    with pytest.raises(TypeError):
        Finding("TEST", "LOW", "Description", "Evidence", True)


def test_finding_is_immutable():
    finding = Finding(
        "TEST", "LOW", "Description", "Evidence", 10
    )

    with pytest.raises(AttributeError):
        finding.score = 50

def test_reject_non_string_severity():
    with pytest.raises(TypeError):
        Finding("TEST", 123, "Description", "Evidence", 10)


def test_reject_unhashable_severity():
    with pytest.raises(TypeError):
        Finding("TEST", [], "Description", "Evidence", 10)


def test_reject_non_string_type():
    with pytest.raises(ValueError):
        Finding(None, "LOW", "Description", "Evidence", 10)


def test_reject_non_string_description():
    with pytest.raises(TypeError):
        Finding("TEST", "LOW", None, "Evidence", 10)


def test_reject_non_string_evidence():
    with pytest.raises(TypeError):
        Finding("TEST", "LOW", "Description", None, 10)


def test_reject_float_score():
    with pytest.raises(TypeError):
        Finding("TEST", "LOW", "Description", "Evidence", 10.5)
