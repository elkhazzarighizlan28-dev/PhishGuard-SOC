
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlparse
import ipaddress


SUPPORTED_IOC_TYPES = {"ip", "domain", "url", "sha256"}


@dataclass(frozen=True, slots=True)
class IOC:
    value: str
    ioc_type: str

    def __post_init__(self):
        if not isinstance(self.value, str) or not self.value.strip():
            raise ValueError("IOC value must be a non-empty string")

        if self.ioc_type not in SUPPORTED_IOC_TYPES:
            raise ValueError("Unsupported IOC type")

        object.__setattr__(self, "value", self.value.strip())


@dataclass(frozen=True, slots=True)
class ThreatIntelResult:
    ioc: IOC
    provider: str
    verdict: str
    confidence: int
    reference: str = ""

    def __post_init__(self):
        allowed = {"MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN"}

        if self.verdict not in allowed:
            raise ValueError("Invalid threat intelligence verdict")

        if type(self.confidence) is not int:
            raise ValueError("Confidence must be an integer")

        if not 0 <= self.confidence <= 100:
            raise ValueError("Confidence must be between 0 and 100")


class ThreatIntelProvider(Protocol):
    name: str

    def lookup(self, ioc: IOC) -> ThreatIntelResult:
        ...


def normalize_ioc(value: str, ioc_type: str) -> IOC:
    value = value.strip()

    if ioc_type == "ip":
        return IOC(str(ipaddress.ip_address(value)), "ip")

    if ioc_type == "domain":
        domain = value.lower().rstrip(".")

        if not domain or "/" in domain or " " in domain:
            raise ValueError("Invalid domain IOC")

        return IOC(domain, "domain")

    if ioc_type == "url":
        parsed = urlparse(value)

        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Invalid URL IOC")

        return IOC(value, "url")

    if ioc_type == "sha256":
        digest = value.lower()

        if len(digest) != 64:
            raise ValueError("Invalid SHA-256 length")

        try:
            int(digest, 16)
        except ValueError as exc:
            raise ValueError("Invalid SHA-256 digest") from exc

        return IOC(digest, "sha256")

    raise ValueError("Unsupported IOC type")


def result_to_dict(result: ThreatIntelResult) -> dict:
    return {
        "ioc": result.ioc.value,
        "ioc_type": result.ioc.ioc_type,
        "provider": result.provider,
        "verdict": result.verdict,
        "confidence": result.confidence,
        "reference": result.reference,
    }
