import re
from email.utils import parseaddr
from typing import Any
from urllib.parse import urlparse

from src.auth_analyzer import (
    analyze_authentication,
    build_auth_findings,
)
from src.schemas import Finding


RISK_THRESHOLDS = (
    ("CRITICAL", 70),
    ("HIGH", 40),
    ("MEDIUM", 20),
)


URGENCY_KEYWORDS = [
    "urgent",
    "immediately",
    "verify",
    "suspended",
    "locked",
    "password",
    "within 24 hours",
    "act now",
    "confirm your account",
]

SUSPICIOUS_BRANDS = [
    "paypal",
    "microsoft",
    "google",
    "amazon",
    "apple",
]

SUSPICIOUS_TLDS = [
    ".zip",
    ".click",
    ".top",
    ".work",
]


def extract_urls(text: str) -> list[str]:
    """Extract HTTP and HTTPS URLs from email content."""
    pattern = r"https?://[^\s<>\"']+"
    return re.findall(pattern, text, re.IGNORECASE)


def analyze_reply_to(email: dict[str, Any]) -> Finding | None:
    """Compare normalized sender and Reply-To email addresses."""

    sender_raw = str(email.get("from") or "").strip()
    reply_raw = str(email.get("reply_to") or "").strip()

    sender = parseaddr(sender_raw)[1].casefold()
    reply_to = parseaddr(reply_raw)[1].casefold()

    if not sender or not reply_to:
        return None

    if sender != reply_to:
        return Finding(
            type="REPLY_TO_MISMATCH",
            severity="MEDIUM",
            description="Reply-To address differs from sender.",
            evidence=f"From: {sender} | Reply-To: {reply_to}",
            score=25,
        )

    return None


def analyze_urls(body: str) -> list[Finding]:
    """Detect suspicious URL characteristics."""

    findings: list[Finding] = []

    for url in extract_urls(body):
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        if parsed.scheme == "http":
            findings.append(
                Finding(
                    type="INSECURE_HTTP",
                    severity="LOW",
                    description="URL uses HTTP instead of HTTPS.",
                    evidence=url,
                    score=10,
                )
            )

        if hostname.startswith("xn--") or ".xn--" in hostname:
            findings.append(
                Finding(
                    type="PUNYCODE_DOMAIN",
                    severity="HIGH",
                    description="URL contains a Punycode domain.",
                    evidence=hostname,
                    score=30,
                )
            )

        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hostname):
            findings.append(
                Finding(
                    type="IP_BASED_URL",
                    severity="HIGH",
                    description="URL uses an IP address instead of a domain.",
                    evidence=hostname,
                    score=25,
                )
            )

        if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
            findings.append(
                Finding(
                    type="SUSPICIOUS_TLD",
                    severity="MEDIUM",
                    description="URL uses a potentially risky top-level domain.",
                    evidence=hostname,
                    score=15,
                )
            )

        # Detect brand names embedded in a non-official-looking hostname.
        for brand in SUSPICIOUS_BRANDS:
            if brand in hostname and not (
                hostname == f"{brand}.com"
                or hostname.endswith(f".{brand}.com")
            ):
                findings.append(
                    Finding(
                        type="POSSIBLE_BRAND_IMPERSONATION",
                        severity="HIGH",
                        description=(
                            f"Brand name '{brand}' appears in an unusual domain."
                        ),
                        evidence=hostname,
                        score=30,
                    )
                )
                break

    return findings


def analyze_urgency(body: str) -> Finding | None:
    """Detect pressure and urgency language."""

    text = body.lower()

    matched = [
        keyword
        for keyword in URGENCY_KEYWORDS
        if keyword in text
    ]

    if matched:
        return Finding(
            type="URGENCY_LANGUAGE",
            severity="LOW",
            description="Email contains pressure or urgency language.",
            evidence=", ".join(matched),
            score=10,
        )

    return None


def analyze_email(email: dict[str, Any]) -> dict[str, Any]:
    """Run all detection modules and calculate a risk score."""

    findings: list[Finding] = []

    # 1. Analyse trusted authentication results.
    authentication = analyze_authentication(
        email.get("authentication_results", [])
    )

    # Authentication analyzer preserves its legacy dictionary interface.
    auth_findings = build_auth_findings(authentication)

    findings.extend(
        Finding(**item)
        for item in auth_findings
    )

    # 2. Check sender and Reply-To mismatch.
    reply_finding = analyze_reply_to(email)

    if reply_finding is not None:
        findings.append(reply_finding)

    # 3. Analyse URLs.
    findings.extend(
        analyze_urls(email.get("body", ""))
    )

    # 4. Detect urgency language.
    urgency_finding = analyze_urgency(
        email.get("subject", "") + " " + email.get("body", "")
    )

    if urgency_finding is not None:
        findings.append(urgency_finding)

    # 5. Calculate final risk score once.
    score = min(
        100,
        sum(finding.score for finding in findings)
    )

    # 6. Determine risk level.
    risk_level = "LOW"

    for level, minimum in RISK_THRESHOLDS:
        if score >= minimum:
            risk_level = level
            break

    # Convert Finding objects to the legacy dictionary format.
    legacy_findings = [
        finding.to_dict()
        for finding in findings
    ]

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "findings": legacy_findings,
        "total_findings": len(legacy_findings),
        "authentication": authentication,
    }
