
import pytest

from src.threat_intel import (
    IOC,
    ThreatIntelResult,
    normalize_ioc,
    result_to_dict,
)


def test_normalize_ip():
    result = normalize_ioc("8.8.8.8", "ip")
    assert result.value == "8.8.8.8"


def test_normalize_domain():
    result = normalize_ioc("Example.COM.", "domain")
    assert result.value == "example.com"


def test_normalize_sha256():
    digest = "A" * 64
    result = normalize_ioc(digest, "sha256")
    assert result.value == "a" * 64


def test_reject_invalid_ip():
    with pytest.raises(ValueError):
        normalize_ioc("999.999.999.999", "ip")


def test_reject_invalid_url():
    with pytest.raises(ValueError):
        normalize_ioc("not-a-url", "url")


def test_reject_invalid_sha256():
    with pytest.raises(ValueError):
        normalize_ioc("abc123", "sha256")


def test_reject_unsupported_type():
    with pytest.raises(ValueError):
        normalize_ioc("example.com", "email")


def test_threat_result_validation():
    ioc = IOC("example.com", "domain")

    result = ThreatIntelResult(
        ioc=ioc,
        provider="local-test",
        verdict="SUSPICIOUS",
        confidence=75,
    )

    assert result.verdict == "SUSPICIOUS"
    assert result.confidence == 75


def test_reject_invalid_verdict():
    ioc = IOC("example.com", "domain")

    with pytest.raises(ValueError):
        ThreatIntelResult(
            ioc=ioc,
            provider="test",
            verdict="DANGEROUS",
            confidence=50,
        )


def test_serialize_result():
    ioc = IOC("example.com", "domain")
    result = ThreatIntelResult(
        ioc=ioc,
        provider="test",
        verdict="CLEAN",
        confidence=90,
    )

    data = result_to_dict(result)

    assert data["ioc"] == "example.com"
    assert data["provider"] == "test"
    assert data["verdict"] == "CLEAN"

