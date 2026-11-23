import re
from email.utils import parseaddr
from typing import Any

from src.schemas import Finding


OFFICIAL_BRAND_DOMAINS = {
    "paypal": ("paypal.com",),
    "microsoft": ("microsoft.com",),
    "google": ("google.com",),
    "amazon": ("amazon.com",),
    "apple": ("apple.com",),
}


def analyze_sender_identity(email: dict[str, Any]) -> Finding | None:
    """
    Detect a known brand used in the sender display name
    while the sender email domain is not an official brand domain.
    """

    sender_raw = str(email.get("from") or "").strip()

    if not sender_raw:
        return None

    display_name, sender_address = parseaddr(sender_raw)

    if not display_name or not sender_address or "@" not in sender_address:
        return None

    display_name_normalized = display_name.casefold()
    sender_domain = sender_address.rsplit("@", 1)[1].casefold().rstrip(".")

    if not sender_domain:
        return None

    for brand, official_domains in OFFICIAL_BRAND_DOMAINS.items():
        if not re.search(rf"\b{re.escape(brand)}\b", display_name_normalized):
            continue

        is_official_domain = any(
            sender_domain == domain
            or sender_domain.endswith("." + domain)
            for domain in official_domains
        )

        if not is_official_domain:
            return Finding(
                type="DISPLAY_NAME_BRAND_IMPERSONATION",
                severity="HIGH",
                description=(
                    f"Sender display name references {brand}, "
                    "but the email domain is not an official brand domain."
                ),
                evidence=(
                    f"Display name: {display_name} | "
                    f"Sender domain: {sender_domain}"
                ),
                score=30,
            )

    return None
