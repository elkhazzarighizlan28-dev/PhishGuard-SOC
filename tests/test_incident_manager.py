
import pytest

from src.incident_manager import (
    create_incident,
    get_incident,
    init_db,
    list_incidents,
    update_incident_status,
)


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "test_incidents.db"
    init_db(path)
    return path


@pytest.fixture
def sample_analysis():
    return {
        "risk_score": 75,
        "risk_level": "HIGH",
        "total_findings": 2,
        "findings": [
            {
                "type": "DANGEROUS_ATTACHMENT",
                "severity": "HIGH",
                "description": "Executable attachment detected",
                "evidence": "invoice.exe",
                "score": 35,
            }
        ],
    }


def test_create_and_get_incident(db_path, sample_analysis):
    incident_id = create_incident(
        sample_analysis,
        subject="Suspicious invoice",
        sender="sender@example.com",
        db_path=db_path,
    )

    incident = get_incident(incident_id, db_path)

    assert incident is not None
    assert incident["risk_score"] == 75
    assert incident["risk_level"] == "HIGH"
    assert incident["status"] == "NEW"
    assert incident["analysis"] == sample_analysis


def test_new_incident_is_listed(db_path, sample_analysis):
    create_incident(sample_analysis, db_path=db_path)

    incidents = list_incidents(db_path=db_path)

    assert len(incidents) == 1
    assert incidents[0]["status"] == "NEW"


def test_update_incident_status(db_path, sample_analysis):
    incident_id = create_incident(sample_analysis, db_path=db_path)

    updated = update_incident_status(
        incident_id,
        "INVESTIGATING",
        "Analyst started investigation",
        db_path,
    )

    incident = get_incident(incident_id, db_path)

    assert updated is True
    assert incident["status"] == "INVESTIGATING"
    assert incident["analyst_note"] == "Analyst started investigation"


def test_unknown_incident_returns_none(db_path):
    assert get_incident("unknown-id", db_path) is None


def test_invalid_status_is_rejected(db_path):
    with pytest.raises(ValueError):
        update_incident_status(
            "unknown-id",
            "HACKED",
            db_path=db_path,
        )


def test_invalid_risk_score_is_rejected(db_path):
    with pytest.raises(ValueError):
        create_incident(
            {"risk_score": 150, "risk_level": "HIGH"},
            db_path=db_path,
        )


def test_invalid_limit_is_rejected(db_path):
    with pytest.raises(ValueError):
        list_incidents(limit=0, db_path=db_path)


def test_update_unknown_incident_returns_false(db_path):
    result = update_incident_status(
        "unknown-id",
        "RESOLVED",
        db_path=db_path,
    )

    assert result is False
