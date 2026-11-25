import pytest

from src.schemas import Finding

VALID = {
    "type": "TEST",
    "severity": "LOW",
    "description": "Description",
    "evidence": "Evidence",
    "score": 10,
}


def make_finding(**overrides):
    """Construit un Finding valide en remplaçant uniquement les champs voulus."""
    return Finding(**{**VALID, **overrides})


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


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("type", ""),
        ("type", None),
        ("severity", "INFO"),
        ("score", 101),
        ("score", -1),
    ],
    ids=[
        "empty_type",
        "none_type",
        "invalid_severity",
        "score_above_100",
        "negative_score",
    ],
)
def test_reject_invalid_values(field, value):
    with pytest.raises(ValueError):
        make_finding(**{field: value})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("severity", 123),
        ("severity", []),
        ("description", None),
        ("evidence", None),
        ("score", True),
        ("score", 10.5),
    ],
    ids=[
        "int_severity",
        "unhashable_severity",
        "none_description",
        "none_evidence",
        "boolean_score",
        "float_score",
    ],
)
def test_reject_wrong_types(field, value):
    with pytest.raises(TypeError):
        make_finding(**{field: value})


def test_finding_is_immutable():
    finding = make_finding()

    with pytest.raises(AttributeError):
        setattr(finding, "score", 50)