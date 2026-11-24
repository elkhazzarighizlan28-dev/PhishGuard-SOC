
import pytest

from src.incident_manager import (
    create_incident,
    get_incident,
    init_db,
    list_audit_events,
    list_incidents,
    update_incident_status,
    verify_audit_chain,
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


def test_incident_creation_generates_audit_event(
    db_path, sample_analysis
):
    incident_id = create_incident(
        sample_analysis,
        db_path=db_path,
        actor="analyst-01",
    )

    events = list_audit_events(incident_id, db_path=db_path)

    assert len(events) == 1
    assert events[0]["action"] == "INCIDENT_CREATED"
    assert events[0]["new_status"] == "NEW"
    assert events[0]["actor"] == "analyst-01"


def test_status_change_generates_audit_event(
    db_path, sample_analysis
):
    incident_id = create_incident(
        sample_analysis,
        db_path=db_path,
    )

    update_incident_status(
        incident_id,
        "INVESTIGATING",
        db_path=db_path,
        actor="analyst-02",
    )

    events = list_audit_events(incident_id, db_path=db_path)

    assert len(events) == 2

    status_event = events[0]

    assert status_event["action"] == "STATUS_CHANGED"
    assert status_event["old_status"] == "NEW"
    assert status_event["new_status"] == "INVESTIGATING"
    assert status_event["actor"] == "analyst-02"


def test_same_status_does_not_create_duplicate_event(
    db_path, sample_analysis
):
    incident_id = create_incident(
        sample_analysis,
        db_path=db_path,
    )

    update_incident_status(
        incident_id,
        "NEW",
        db_path=db_path,
    )

    events = list_audit_events(incident_id, db_path=db_path)

    assert len(events) == 1


def test_audit_events_are_empty_for_unknown_incident(db_path):
    events = list_audit_events(
        "unknown-id",
        db_path=db_path,
    )

    assert events == []


def test_invalid_actor_is_rejected(db_path, sample_analysis):
    with pytest.raises(ValueError):
        create_incident(
            sample_analysis,
            db_path=db_path,
            actor="",
        )

def test_audit_chain_is_valid_after_multiple_events(
    db_path, sample_analysis
):
    incident_id = create_incident(
        sample_analysis,
        db_path=db_path,
    )

    update_incident_status(
        incident_id,
        "INVESTIGATING",
        db_path=db_path,
    )

    result = verify_audit_chain(db_path)

    assert result["valid"] is True
    assert result["checked_events"] == 2


def test_audit_chain_detects_event_modification(
    db_path, sample_analysis
):
    incident_id = create_incident(
        sample_analysis,
        db_path=db_path,
    )

    import sqlite3

    connection = sqlite3.connect(db_path)
    try:
        connection.execute("""
            UPDATE incident_audit_logs
            SET actor = 'unauthorized-user'
            WHERE incident_id = ?
        """, (incident_id,))
        connection.commit()
    finally:
        connection.close()

    result = verify_audit_chain(db_path)

    assert result["valid"] is False
    assert result["reason"] == "Event hash mismatch"


def test_audit_chain_detects_middle_event_deletion(
    db_path, sample_analysis
):
    incident_id = create_incident(
        sample_analysis,
        db_path=db_path,
    )

    update_incident_status(
        incident_id,
        "INVESTIGATING",
        db_path=db_path,
    )

    import sqlite3

    connection = sqlite3.connect(db_path)
    try:
        connection.execute("""
            DELETE FROM incident_audit_logs
            WHERE incident_id = ?
              AND action = 'INCIDENT_CREATED'
        """, (incident_id,))
        connection.commit()
    finally:
        connection.close()

    result = verify_audit_chain(db_path)

    assert result["valid"] is False
