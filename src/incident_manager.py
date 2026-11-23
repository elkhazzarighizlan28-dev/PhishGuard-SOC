
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


def get_connection(db_path: str | Path = DEFAULT_DB_PATH):
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
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

        connection.commit()
    finally:
        connection.close()


def create_incident(
    analysis: dict[str, Any],
    subject: str = "",
    sender: str = "",
    db_path: str | Path = DEFAULT_DB_PATH,
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

    analysis_json = json.dumps(
        analysis,
        ensure_ascii=False,
        separators=(",", ":"),
    )

    incident_id = str(uuid.uuid4())
    now = utc_now()

    connection = get_connection(db_path)

    try:
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
        connection.commit()
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
        incident["analysis"] = json.loads(incident.pop("analysis_json"))
        return incident
    finally:
        connection.close()


def update_incident_status(
    incident_id: str,
    status: str,
    analyst_note: str = "",
    db_path: str | Path = DEFAULT_DB_PATH,
) -> bool:
    normalized_status = status.upper()

    if normalized_status not in INCIDENT_STATUSES:
        raise ValueError("Unsupported incident status")

    if not isinstance(analyst_note, str):
        raise TypeError("analyst_note must be a string")

    connection = get_connection(db_path)

    try:
        cursor = connection.execute(
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

        connection.commit()
        return cursor.rowcount == 1
    finally:
        connection.close()
