from typing import Any


MITRE_TECHNIQUES = {
    "DISPLAY_NAME_BRAND_IMPERSONATION": {
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/",
    },
    "DOMAIN_SIMILARITY": {
        "technique_id": "T1583.001",
        "technique_name": "Domains",
        "tactic": "Resource Development",
        "url": "https://attack.mitre.org/techniques/T1583/001/",
    },
    "POSSIBLE_BRAND_IMPERSONATION": {
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/",
    },
    "DANGEROUS_ATTACHMENT": {
        "technique_id": "T1566.001",
        "technique_name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/001/",
    },
    "DOUBLE_EXTENSION_ATTACHMENT": {
        "technique_id": "T1036",
        "technique_name": "Masquerading",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1036/",
    },
    "MACRO_ENABLED_ATTACHMENT": {
        "technique_id": "T1204.002",
        "technique_name": "Malicious File",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1204/002/",
    },
    "REPLY_TO_MISMATCH": {
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/",
    },
    "INSECURE_HTTP": {
        "technique_id": "T1566.002",
        "technique_name": "Spearphishing Link",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/002/",
    },
}


def map_finding_to_mitre(
    finding: dict[str, Any],
) -> dict[str, Any] | None:
    """Map a supported detection finding to a MITRE ATT&CK reference."""

    finding_type = finding.get("type")

    technique = MITRE_TECHNIQUES.get(finding_type)

    if technique is None:
        return None

    return {
        "finding_type": finding_type,
        **technique,
    }


def map_findings_to_mitre(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Map findings and avoid duplicate technique references."""

    mapped = []
    seen = set()

    for finding in findings:
        result = map_finding_to_mitre(finding)

        if result is None:
            continue

        technique_id = result["technique_id"]

        if technique_id in seen:
            continue

        seen.add(technique_id)
        mapped.append(result)

    return mapped
