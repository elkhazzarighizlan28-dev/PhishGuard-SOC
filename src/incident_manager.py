import hashlib
import hmac
import json
import sqlite3
import uuid

from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_DB_PATH = Path("data/incidents.db")

INCIDENT_STATUSES = {
    "NEW",
    "INVESTIGATING",
    "RESOLVED",
    "FALSE_POSITIVE",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()



def _calculate_audit_hash(
    event_id: int,
    incident_id: str,
    actor: str,
    action: str,
    old_status: str | None,
    new_status: str | None,
    created_at: str,
    previous_hash: str | None,
) -> str:
    payload = {
        "id": event_id,
        "incident_id": incident_id,
        "actor": actor,
        "action": action,
        "old_status": old_status,
        "new_status": new_status,
        "created_at": created_at,
        "previous_hash": previous_hash,
    }

    canonical_data = json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(canonical_data).hexdigest()

def get_connection(db_path: str | Path = DEFAULT_DB_PATH):
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def init_db(db_path: str | Path = DEFAULT_DB_PATH) -> None:
    connection = get_connection(db_path)

    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                subject TEXT NOT NULL DEFAULT '',
                sender TEXT NOT NULL DEFAULT '',
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'NEW',
                analysis_json TEXT NOT NULL,
                analyst_note TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_incidents_status
            ON incidents(status)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_incidents_created
            ON incidents(created_at)
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS incident_audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                old_status TEXT,
                new_status TEXT,
                created_at TEXT NOT NULL,
                previous_hash TEXT,
                event_hash TEXT,
                FOREIGN KEY (incident_id)
                    REFERENCES incidents(id)
                    ON DELETE CASCADE
            )
        """)

        audit_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(incident_audit_logs)"
            ).fetchall()
        }

        if "previous_hash" not in audit_columns:
            connection.execute(
                "ALTER TABLE incident_audit_logs ADD COLUMN previous_hash TEXT"
            )

        if "event_hash" not in audit_columns:
            connection.execute(
                "ALTER TABLE incident_audit_logs ADD COLUMN event_hash TEXT"
            )

        # Backfill only a completely legacy chain.
        legacy_events = connection.execute("""
            SELECT id, incident_id, actor, action,
                   old_status, new_status, created_at
            FROM incident_audit_logs
            ORDER BY id
        """).fetchall()

        if legacy_events and all(
            connection.execute(
                "SELECT previous_hash, event_hash "
                "FROM incident_audit_logs WHERE id = ?",
                (event["id"],),
            ).fetchone()["event_hash"] is None
            for event in legacy_events
        ):
            previous_hash = None

            for event in legacy_events:
                event_hash = _calculate_audit_hash(
                    event_id=event["id"],
                    incident_id=event["incident_id"],
                    actor=event["actor"],
                    action=event["action"],
                    old_status=event["old_status"],
                    new_status=event["new_status"],
                    created_at=event["created_at"],
                    previous_hash=previous_hash,
                )

                connection.execute("""
                    UPDATE incident_audit_logs
                    SET previous_hash = ?, event_hash = ?
                    WHERE id = ?
                """, (previous_hash, event_hash, event["id"]))

                previous_hash = event_hash

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_incident
            ON incident_audit_logs(incident_id, created_at)
        """)

        connection.commit()
    finally:
        connection.close()


def _validate_actor(actor: str) -> str:
    if not isinstance(actor, str) or not actor.strip():
        raise ValueError("actor must be a non-empty string")

    return actor.strip()[:100]


def _record_audit_event(
    connection,
    incident_id: str,
    actor: str,
    action: str,
    old_status: str | None = None,
    new_status: str | None = None,
) -> None:
    previous_event = connection.execute("""
        SELECT event_hash
        FROM incident_audit_logs
        ORDER BY id DESC
        LIMIT 1
    """).fetchone()

    previous_hash = (
        previous_event["event_hash"]
        if previous_event is not None
        else None
    )

    if previous_event is not None and not previous_hash:
        raise RuntimeError(
            "Cannot extend an audit chain with an invalid previous event."
        )

    created_at = utc_now()

    cursor = connection.execute("""
        INSERT INTO incident_audit_logs (
            incident_id, actor, action,
            old_status, new_status, created_at,
            previous_hash, event_hash
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
    """, (
        incident_id,
        actor,
        action,
        old_status,
        new_status,
        created_at,
        previous_hash,
    ))

    event_id = cursor.lastrowid

    event_hash = _calculate_audit_hash(
        event_id=event_id,
        incident_id=incident_id,
        actor=actor,
        action=action,
        old_status=old_status,
        new_status=new_status,
        created_at=created_at,
        previous_hash=previous_hash,
    )

    connection.execute("""
        UPDATE incident_audit_logs
        SET event_hash = ?
        WHERE id = ?
    """, (event_hash, event_id))


def create_incident(
    analysis: dict[str, Any],
    subject: str = "",
    sender: str = "",
    db_path: str | Path = DEFAULT_DB_PATH,
    actor: str = "local-analyst",
) -> str:
    if not isinstance(analysis, dict):
        raise TypeError("analysis must be a dictionary")

    score = analysis.get("risk_score")
    level = analysis.get("risk_level")

    if type(score) is not int or not 0 <= score <= 100:
        raise ValueError("risk_score must be an integer between 0 and 100")

    if not isinstance(level, str) or not level.strip():
        raise ValueError("risk_level must be a non-empty string")

    if not isinstance(subject, str) or not isinstance(sender, str):
        raise TypeError("subject and sender must be strings")

    actor = _validate_actor(actor)

    analysis_json = json.dumps(
        analysis,
        ensure_ascii=False,
        separators=(",", ":"),
    )

    incident_id = str(uuid.uuid4())
    now = utc_now()

    connection = get_connection(db_path)

    try:
        with connection:
            connection.execute(
                """
                INSERT INTO incidents (
                    id, subject, sender, risk_score, risk_level,
                    status, analysis_json, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, 'NEW', ?, ?, ?)
                """,
                (
                    incident_id,
                    subject[:500],
                    sender[:500],
                    score,
                    level.upper(),
                    analysis_json,
                    now,
                    now,
                ),
            )

            _record_audit_event(
                connection=connection,
                incident_id=incident_id,
                actor=actor,
                action="INCIDENT_CREATED",
                old_status=None,
                new_status="NEW",
            )
    finally:
        connection.close()

    return incident_id


def list_incidents(
    limit: int = 100,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> list[dict[str, Any]]:
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("limit must be between 1 and 1000")

    connection = get_connection(db_path)

    try:
        rows = connection.execute(
            """
            SELECT id, subject, sender, risk_score, risk_level,
                   status, analyst_note, created_at, updated_at
            FROM incidents
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        return [dict(row) for row in rows]
    finally:
        connection.close()


def get_incident(
    incident_id: str,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> dict[str, Any] | None:
    connection = get_connection(db_path)

    try:
        row = connection.execute(
            "SELECT * FROM incidents WHERE id = ?",
            (incident_id,),
        ).fetchone()

        if row is None:
            return None

        incident = dict(row)
        incident["analysis"] = json.loads(
            incident.pop("analysis_json")
        )

        return incident
    finally:
        connection.close()


def update_incident_status(
    incident_id: str,
    status: str,
    analyst_note: str = "",
    db_path: str | Path = DEFAULT_DB_PATH,
    actor: str = "local-analyst",
) -> bool:
    if not isinstance(status, str):
        raise TypeError("status must be a string")

    normalized_status = status.upper()

    if normalized_status not in INCIDENT_STATUSES:
        raise ValueError("Unsupported incident status")

    if not isinstance(analyst_note, str):
        raise TypeError("analyst_note must be a string")

    actor = _validate_actor(actor)

    connection = get_connection(db_path)

    try:
        with connection:
            row = connection.execute(
                "SELECT status FROM incidents WHERE id = ?",
                (incident_id,),
            ).fetchone()

            if row is None:
                return False

            old_status = row["status"]

            connection.execute(
                """
                UPDATE incidents
                SET status = ?, analyst_note = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    normalized_status,
                    analyst_note[:5000],
                    utc_now(),
                    incident_id,
                ),
            )

            if old_status != normalized_status:
                _record_audit_event(
                    connection=connection,
                    incident_id=incident_id,
                    actor=actor,
                    action="STATUS_CHANGED",
                    old_status=old_status,
                    new_status=normalized_status,
                )

        return True
    finally:
        connection.close()


def list_audit_events(
    incident_id: str,
    limit: int = 100,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> list[dict[str, Any]]:
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("limit must be between 1 and 1000")

    connection = get_connection(db_path)

    try:
        rows = connection.execute(
            """
            SELECT id, incident_id, actor, action,
                   old_status, new_status, created_at
            FROM incident_audit_logs
            WHERE incident_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (incident_id, limit),
        ).fetchall()

        return [dict(row) for row in rows]
    finally:
        connection.close()

def verify_audit_chain(
    db_path: str | Path = DEFAULT_DB_PATH,
) -> dict[str, Any]:
    connection = get_connection(db_path)

    try:
        events = connection.execute("""
            SELECT id, incident_id, actor, action,
                   old_status, new_status, created_at,
                   previous_hash, event_hash
            FROM incident_audit_logs
            ORDER BY id
        """).fetchall()

        expected_previous_hash = None

        for event in events:
            if event["previous_hash"] != expected_previous_hash:
                return {
                    "valid": False,
                    "checked_events": len(events),
                    "invalid_event_id": event["id"],
                    "reason": "Previous hash mismatch",
                }

            expected_hash = _calculate_audit_hash(
                event_id=event["id"],
                incident_id=event["incident_id"],
                actor=event["actor"],
                action=event["action"],
                old_status=event["old_status"],
                new_status=event["new_status"],
                created_at=event["created_at"],
                previous_hash=event["previous_hash"],
            )

            stored_hash = event["event_hash"] or ""

            if not hmac.compare_digest(expected_hash, stored_hash):
                return {
                    "valid": False,
                    "checked_events": len(events),
                    "invalid_event_id": event["id"],
                    "reason": "Event hash mismatch",
                }

            expected_previous_hash = stored_hash

        return {
            "valid": True,
            "checked_events": len(events),
            "invalid_event_id": None,
            "reason": "Audit chain integrity verified",
        }

    finally:
        connection.close()
