from difflib import SequenceMatcher
from email.utils import parseaddr
from typing import Any

from src.schemas import Finding
from src.sender_analyzer import OFFICIAL_BRAND_DOMAINS


SIMILARITY_THRESHOLD = 0.75

CONFUSABLE_CHARACTERS = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "7": "t",
})


def normalize_domain_label(label: str) -> str:
    """Normalize common digit-to-letter substitutions."""
    return label.casefold().translate(CONFUSABLE_CHARACTERS)


def calculate_similarity(first: str, second: str) -> float:
    """Calculate similarity after normalizing common confusable characters."""
    normalized_first = normalize_domain_label(first)
    normalized_second = normalize_domain_label(second)

    return SequenceMatcher(
        None,
        normalized_first,
        normalized_second
    ).ratio()


def analyze_domain_similarity(email: dict[str, Any]) -> Finding | None:
    """
    Detect sender domains that resemble known official brand domains.

    This is a heuristic, not proof of malicious activity.
    """

    sender_raw = str(email.get("from") or "").strip()

    if not sender_raw:
        return None

    _, sender_address = parseaddr(sender_raw)

    if "@" not in sender_address:
        return None

    sender_domain = (
        sender_address.rsplit("@", 1)[1]
        .casefold()
        .rstrip(".")
    )

    labels = sender_domain.split(".")

    if len(labels) < 2 or any(not label for label in labels):
        return None

    # Current official brand domains use .com.
    candidate_label = labels[-2]

    for brand, official_domains in OFFICIAL_BRAND_DOMAINS.items():
        for official_domain in official_domains:
            official_labels = official_domain.split(".")

            if len(official_labels) < 2:
                continue

            official_label = official_labels[-2]

            # Do not flag official domains or their subdomains.
            if (
                sender_domain == official_domain
                or sender_domain.endswith("." + official_domain)
            ):
                return None

            similarity = calculate_similarity(
                candidate_label,
                official_label
            )

            if (
                candidate_label != official_label
                and similarity >= SIMILARITY_THRESHOLD
            ):
                return Finding(
                    type="DOMAIN_SIMILARITY",
                    severity="HIGH",
                    description=(
                        f"Sender domain resembles the official "
                        f"{brand} domain."
                    ),
                    evidence=(
                        f"Sender domain: {sender_domain} | "
                        f"Possible target: {official_domain} | "
                        f"Similarity: {similarity:.2f}"
                    ),
                    score=30,
                )

    return None
