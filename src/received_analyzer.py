"""Analyse de la chaîne d'en-têtes Received d'un e-mail (parcours entre serveurs)."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from typing import Any

MAX_HOPS = 50
MAX_IPS_PER_HOP = 5
MAX_HOST_LEN = 255
SLOW_HOP_SECONDS = 3600   # au-delà : délai anormal entre deux sauts
MANY_HOPS = 15            # au-delà : nombre de sauts inhabituel

FROM_RE = re.compile(r"\bfrom\s+([^\s(;]+)", re.IGNORECASE)
BY_RE = re.compile(r"\bby\s+([^\s(;]+)", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
BIDI_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")


def _clean(value: str, limit: int) -> str:
    return CONTROL_RE.sub("", BIDI_RE.sub("", value))[:limit]


def _parse_time(raw: str) -> datetime | None:
    """Lit la date après le dernier « ; » de l'en-tête et la convertit en UTC."""
    if ";" not in raw:
        return None
    stamp = raw.rsplit(";", 1)[-1].strip()
    if not stamp:
        return None
    try:
        parsed = parsedate_to_datetime(stamp)
    except (TypeError, ValueError, IndexError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _extract_ips(text: str) -> list[ipaddress.IPv4Address]:
    found: list[ipaddress.IPv4Address] = []
    for candidate in IPV4_RE.findall(text):
        try:
            address = ipaddress.IPv4Address(candidate)
        except ValueError:
            continue
        if address not in found:
            found.append(address)
    return found[:MAX_IPS_PER_HOP]


def analyze_received(data: bytes) -> dict[str, Any]:
    """
    Retourne les sauts dans l'ordre chronologique (origine en premier).

    Attention : seuls les en-têtes Received ajoutés par VOTRE serveur sont fiables.
    Ceux situés plus bas dans le message ont pu être inventés par l'expéditeur.
    """
    result: dict[str, Any] = {
        "hops": [],
        "origin_ip": "",
        "total_delay_s": None,
        "notes": [],
    }

    try:
        msg = BytesParser(policy=policy.default).parsebytes(data, headersonly=True)
        headers = [str(value) for value in (msg.get_all("Received") or [])]
    except Exception:  # noqa: BLE001
        result["notes"].append("Les en-têtes Received sont illisibles.")
        return result

    if not headers:
        result["notes"].append(
            "Aucun en-tête Received : message généré localement ou en-têtes supprimés."
        )
        return result

    total_headers = len(headers)
    # Le plus haut est le plus récent : on garde les plus anciens et on inverse.
    ordered = [" ".join(h.split()) for h in reversed(headers[-MAX_HOPS:])]

    times: list[datetime] = []
    previous_time: datetime | None = None
    has_negative = False

    for number, raw in enumerate(ordered, start=1):
        header_part = raw.split(";", 1)[0]
        moment = _parse_time(raw)
        ips = _extract_ips(header_part)
        flags: list[str] = []
        delay: int | None = None

        if moment is None:
            flags.append("date illisible")
        else:
            if previous_time is not None:
                delay = int((moment - previous_time).total_seconds())
                if delay < 0:
                    flags.append("délai négatif")
                    has_negative = True
                elif delay > SLOW_HOP_SECONDS:
                    flags.append("délai > 1 h")
            previous_time = moment
            times.append(moment)

        from_match = FROM_RE.search(header_part)
        by_match = BY_RE.search(header_part)

        result["hops"].append({
            "hop": number,
            "from": _clean(from_match.group(1), MAX_HOST_LEN) if from_match else "",
            "by": _clean(by_match.group(1), MAX_HOST_LEN) if by_match else "",
            "ips": [str(ip) for ip in ips],
            "time": moment.isoformat(timespec="seconds") if moment else "",
            "delay_s": delay,
            "flags": flags,
        })

        if not result["origin_ip"]:
            for ip in ips:
                if ip.is_global:
                    result["origin_ip"] = str(ip)
                    break

    if len(times) >= 2:
        result["total_delay_s"] = int((times[-1] - times[0]).total_seconds())

    if has_negative:
        result["notes"].append(
            "Horodatages incohérents entre deux sauts : falsification ou horloge mal réglée possible."
        )
    if total_headers > MANY_HOPS:
        result["notes"].append(f"Nombre de sauts élevé ({total_headers}).")
    if total_headers > MAX_HOPS:
        result["notes"].append(f"Seuls les {MAX_HOPS} sauts les plus anciens sont analysés.")

    return result