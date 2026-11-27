"""Pont entre l'analyse d'un e-mail (app.py) et la base d'incidents (incident_manager.py)."""

from __future__ import annotations

from typing import Any, Callable, Mapping

from src.incident_manager import (
    create_incident,
    get_incident,
    init_db,
    list_incidents,
)

MAX_SCAN = 1000

# Correspondance indicative catégorie de menace -> technique MITRE ATT&CK.
MITRE_BY_CATEGORY = {
    "Authentification": {
        "technique_id": "T1672",
        "technique_name": "Email Spoofing",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1672/",
    },
    "Liens & URL": {
        "technique_id": "T1566.002",
        "technique_name": "Spearphishing Link",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/002/",
    },
    "Expéditeur": {
        "technique_id": "T1656",
        "technique_name": "Impersonation",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1656/",
    },
    "Pièces jointes": {
        "technique_id": "T1566.001",
        "technique_name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/001/",
    },
    "Ingénierie sociale": {
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/",
    },
}


def build_incident_payload(
    analysis: Mapping[str, Any],
    sha256: str,
    defang: Callable[[str], str],
) -> dict[str, Any]:
    """Construit le dictionnaire stocké dans la base (format attendu par le dashboard)."""
    result = analysis["result"]
    profile = analysis.get("profile", {})

    return {
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "evidence_sha256": sha256,
        "findings": [
            {
                **finding,
                "description": defang(finding["description"]),
                "evidence": defang(finding["evidence"]),
            }
            for finding in result["findings"]
        ],
        "mitre_techniques": [
            dict(MITRE_BY_CATEGORY[category])
            for category, value in profile.items()
            if value > 0 and category in MITRE_BY_CATEGORY
        ],
        "attachments": [],
        "authentication": result["authentication"],
        "header_notes": list(analysis.get("header_notes", [])),
        "threat_profile": dict(profile),
        "indicators": [
            {**row, "Valeur": defang(row["Valeur"])} for row in analysis.get("iocs", [])
        ],
    }


def find_incident_by_hash(sha256: str) -> str | None:
    """Retourne l'id d'un incident déjà créé pour ce même fichier .eml, sinon None."""
    for item in list_incidents(limit=MAX_SCAN):
        full = get_incident(item["id"])
        stored = (full or {}).get("analysis") or {}
        if stored.get("evidence_sha256") == sha256:
            return item["id"]
    return None


def save_analysis_as_incident(
    analysis: Mapping[str, Any],
    sha256: str,
    defang: Callable[[str], str],
    actor: str = "local-analyst",
) -> tuple[str, bool]:
    """Enregistre l'analyse. Retourne (id_incident, créé) ; créé=False si doublon."""
    init_db()

    existing = find_incident_by_hash(sha256)
    if existing is not None:
        return existing, False

    email = analysis["email"]
    incident_id = create_incident(
        build_incident_payload(analysis, sha256, defang),
        subject=defang(email["subject"]),
        sender=defang(email["from"]),
        actor=actor,
    )
    return incident_id, True