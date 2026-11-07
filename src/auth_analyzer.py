
import re
from collections.abc import Sequence
from typing import Any


AUTH_METHODS = ("spf", "dkim", "dmarc")

VALID_RESULTS = {
    "pass",
    "fail",
    "softfail",
    "neutral",
    "none",
    "temperror",
    "permerror",
}

RESULT_PATTERN = {
    method: re.compile(
        rf"(?<![\w-]){method}\s*=\s*"
        rf"(pass|fail|softfail|neutral|none|temperror|permerror)"
        rf"(?![\w-])",
        re.IGNORECASE,
    )
    for method in AUTH_METHODS
}


def analyze_authentication(
    authentication_results: Sequence[str] | None,
) -> dict[str, Any]:
    """
    Analyse uniquement les en-têtes Authentication-Results
    déjà validés comme provenant d'une source de confiance.

    Un résultat absent devient 'unknown'.
    Plusieurs résultats contradictoires deviennent 'conflict'.
    """

    collected = {method: [] for method in AUTH_METHODS}

    if isinstance(authentication_results, Sequence) and not isinstance(
        authentication_results, (str, bytes)
    ):
        for header in authentication_results:
            if not isinstance(header, str):
                continue

            for method, pattern in RESULT_PATTERN.items():
                matches = pattern.findall(header)

                for match in matches:
                    result = match.lower()
                    if result in VALID_RESULTS:
                        collected[method].append(result)

    summary = {}

    for method, results in collected.items():
        unique_results = set(results)

        if not unique_results:
            summary[method] = "unknown"
        elif len(unique_results) > 1:
            summary[method] = "conflict"
        else:
            summary[method] = results[0]

    return summary
def build_auth_findings(authentication: dict[str, str]) -> list[dict[str, Any]]:
    """Convert authentication results into security findings."""

    findings = []

    rules = {
        "spf": {
            "fail": ("MEDIUM", 20),
            "softfail": ("LOW", 10),
            "conflict": ("MEDIUM", 15),
        },
        "dkim": {
            "fail": ("MEDIUM", 20),
            "softfail": ("LOW", 10),
            "conflict": ("MEDIUM", 15),
        },
        "dmarc": {
            "fail": ("HIGH", 30),
            "softfail": ("MEDIUM", 15),
            "conflict": ("MEDIUM", 15),
        },
    }

    for method, statuses in rules.items():
        status = authentication.get(method, "unknown")

        if status not in statuses:
            continue

        severity, score = statuses[status]

        findings.append({
            "type": f"{method.upper()}_{status.upper()}",
            "severity": severity,
            "description": (
                f"{method.upper()} authentication returned {status}."
            ),
            "evidence": f"{method}={status}",
            "score": score,
        })

    return findings