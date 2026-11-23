
import json
import pytest

from src.report_generator import (
    build_report_data,
    calculate_sha256,
    generate_json_report,
    generate_pdf_report,
)


@pytest.fixture
def incident():
    return {
        "id": "incident-test-001",
        "subject": "Suspicious invoice",
        "sender": "attacker@example.com",
        "risk_score": 80,
        "risk_level": "CRITICAL",
        "status": "INVESTIGATING",
        "created_at": "2026-11-23T10:00:00+00:00",
        "updated_at": "2026-11-23T11:00:00+00:00",
        "analyst_note": "Under investigation.",
        "analysis": {
            "findings": [
                {
                    "type": "DANGEROUS_ATTACHMENT",
                    "severity": "HIGH",
                    "description": "Executable attachment detected",
                    "evidence": "invoice.exe",
                    "score": 35,
                }
            ],
            "mitre_techniques": [],
            "attachments": [],
            "authentication": {},
        },
    }


def test_build_report_data(incident):
    result = build_report_data(incident)

    assert result["incident"]["id"] == "incident-test-001"
    assert len(result["findings"]) == 1


def test_json_report_is_valid(incident):
    result = generate_json_report(incident)
    decoded = json.loads(result.decode("utf-8"))

    assert decoded["incident"]["risk_score"] == 80
    assert decoded["findings"][0]["type"] == "DANGEROUS_ATTACHMENT"


def test_pdf_report_is_generated(incident):
    result = generate_pdf_report(incident)

    assert result.startswith(b"%PDF")
    assert len(result) > 500


def test_sha256_is_deterministic():
    first = calculate_sha256(b"PhishGuard")
    second = calculate_sha256(b"PhishGuard")

    assert first == second
    assert len(first) == 64


def test_sha256_rejects_non_bytes():
    with pytest.raises(TypeError):
        calculate_sha256("PhishGuard")


def test_build_report_rejects_invalid_input():
    with pytest.raises(TypeError):
        build_report_data("invalid")


