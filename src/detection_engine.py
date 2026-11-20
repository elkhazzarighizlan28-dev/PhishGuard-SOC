from src.auth_analyzer import (
    analyze_authentication,
    build_auth_findings,
)
import re
from urllib.parse import urlparse


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


def extract_urls(text):
    """Extract HTTP and HTTPS URLs from email content."""
    pattern = r"https?://[^\s<>\"']+"
    return re.findall(pattern, text, re.IGNORECASE)


def analyze_reply_to(email):
    """Check whether Reply-To differs from sender."""
    sender = email.get("from", "").lower().strip()
    reply_to = email.get("reply_to", "").lower().strip()

    if not sender or not reply_to:
        return None

    if sender != reply_to:
        return {
            "type": "REPLY_TO_MISMATCH",
            "severity": "MEDIUM",
            "description": "Reply-To address differs from sender.",
            "evidence": f"From: {sender} | Reply-To: {reply_to}",
            "score": 25,
        }

    return None


def analyze_urls(body):
    """Detect suspicious URL characteristics."""
    findings = []

    for url in extract_urls(body):
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        if parsed.scheme == "http":
            findings.append({
                "type": "INSECURE_HTTP",
                "severity": "LOW",
                "description": "URL uses HTTP instead of HTTPS.",
                "evidence": url,
                "score": 10,
            })

        if hostname.startswith("xn--") or ".xn--" in hostname:
            findings.append({
                "type": "PUNYCODE_DOMAIN",
                "severity": "HIGH",
                "description": "URL contains a Punycode domain.",
                "evidence": hostname,
                "score": 30,
            })

        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hostname):
            findings.append({
                "type": "IP_BASED_URL",
                "severity": "HIGH",
                "description": "URL uses an IP address instead of a domain.",
                "evidence": hostname,
                "score": 25,
            })

        if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
            findings.append({
                "type": "SUSPICIOUS_TLD",
                "severity": "MEDIUM",
                "description": "URL uses a potentially risky top-level domain.",
                "evidence": hostname,
                "score": 15,
            })

        # Detect brand names embedded in a non-official-looking hostname.
        for brand in SUSPICIOUS_BRANDS:
            if brand in hostname and not (
                hostname == f"{brand}.com"
                or hostname.endswith(f".{brand}.com")
            ):
                findings.append({
                    "type": "POSSIBLE_BRAND_IMPERSONATION",
                    "severity": "HIGH",
                    "description": f"Brand name '{brand}' appears in an unusual domain.",
                    "evidence": hostname,
                    "score": 30,
                })
                break

    return findings


def analyze_urgency(body):
    """Detect pressure and urgency language."""
    text = body.lower()
    matched = [
        keyword
        for keyword in URGENCY_KEYWORDS
        if keyword in text
    ]

    if matched:
        return {
            "type": "URGENCY_LANGUAGE",
            "severity": "LOW",
            "description": "Email contains pressure or urgency language.",
            "evidence": ", ".join(matched),
            "score": 10,
        }

    return None

def analyze_email(email):
    """Run all detection modules and calculate a risk score."""

    findings = []

    # 1. Analyse trusted authentication results
    authentication = analyze_authentication(
        email.get("authentication_results", [])
    )

    findings.extend(
        build_auth_findings(authentication)
    )

    # 2. Check sender and Reply-To mismatch
    reply_finding = analyze_reply_to(email)
    if reply_finding:
        findings.append(reply_finding)

    # 3. Analyse URLs
    findings.extend(
        analyze_urls(email.get("body", ""))
    )

    # 4. Detect urgency language
    urgency_finding = analyze_urgency(
        email.get("subject", "") + " " + email.get("body", "")
    )

    if urgency_finding:
        findings.append(urgency_finding)

    # 5. Calculate final risk score once
    score = min(
        100,
        sum(finding["score"] for finding in findings)
    )

    # 6. Determine risk level
    if score >= 70:
        risk_level = "CRITICAL"
    elif score >= 40:
        risk_level = "HIGH"
    elif score >= 20:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "findings": findings,
        "total_findings": len(findings),
        "authentication": authentication,
    }

def test_spf_failure_creates_finding():
    email = {
        "from": "attacker@example.com",
        "reply_to": "",
        "subject": "Hello",
        "body": "Normal message",
        "authentication_results": [
            "mx.example.com; spf=fail"
        ],
    }

    result = analyze_email(email)

    assert any(
        finding["type"] == "SPF_FAIL"
        for finding in result["findings"]
    )


def test_dmarc_failure_increases_risk_score():
    email = {
        "from": "attacker@example.com",
        "reply_to": "",
        "subject": "Hello",
        "body": "Normal message",
        "authentication_results": [
            "mx.example.com; dmarc=fail"
        ],
    }

    result = analyze_email(email)

    assert result["risk_score"] == 30
    assert result["risk_level"] == "MEDIUM"



