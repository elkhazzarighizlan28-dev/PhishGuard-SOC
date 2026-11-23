from src.mitre_mapper import (
    map_finding_to_mitre,
    map_findings_to_mitre,
)


def test_map_display_name_impersonation():
    finding = {
        "type": "DISPLAY_NAME_BRAND_IMPERSONATION",
        "severity": "HIGH",
    }

    result = map_finding_to_mitre(finding)

    assert result is not None
    assert result["technique_id"] == "T1566"
    assert result["tactic"] == "Initial Access"


def test_map_domain_similarity():
    finding = {"type": "DOMAIN_SIMILARITY"}

    result = map_finding_to_mitre(finding)

    assert result is not None
    assert result["technique_id"] == "T1583.001"


def test_map_dangerous_attachment():
    finding = {"type": "DANGEROUS_ATTACHMENT"}

    result = map_finding_to_mitre(finding)

    assert result is not None
    assert result["technique_id"] == "T1566.001"


def test_map_unknown_finding():
    finding = {"type": "UNKNOWN_DETECTION"}

    assert map_finding_to_mitre(finding) is None


def test_remove_duplicate_techniques():
    findings = [
        {"type": "DISPLAY_NAME_BRAND_IMPERSONATION"},
        {"type": "REPLY_TO_MISMATCH"},
        {"type": "DANGEROUS_ATTACHMENT"},
    ]

    results = map_findings_to_mitre(findings)

    technique_ids = [
        item["technique_id"]
        for item in results
    ]

    assert len(technique_ids) == len(set(technique_ids))
    assert "T1566" in technique_ids
    assert "T1566.001" in technique_ids


def test_empty_findings():
    assert map_findings_to_mitre([]) == []
