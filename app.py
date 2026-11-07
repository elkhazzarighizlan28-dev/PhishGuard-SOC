"""
PhishGuard SOC — plateforme d'analyse et d'investigation d'e-mails suspects.

Principes de sécurité appliqués dans ce fichier :
  * Aucun contenu d'e-mail n'est jamais rendu en HTML ni en Markdown
    (évite XSS, liens piégés et pixels de tracking distants).
  * Les fichiers importés restent en mémoire : rien n'est écrit sur disque.
  * Taille, extension et structure du fichier sont validées avant l'analyse.
  * Les caractères de contrôle et de bidirectionnalité (spoofing visuel)
    sont neutralisés avant l'affichage.
  * Les URLs sont « défangées » par défaut (hxxp, [.]) pour éviter un clic accidentel.
  * Toutes les sorties du moteur de détection sont normalisées et bornées.
  * Empreinte SHA-256 de la preuve et rapport JSON pour la traçabilité.
"""

from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import logging
import os
import re
from collections import Counter
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlparse

import streamlit as st

from src.detection_engine import analyze_email
from src.email_parser import parse_email_bytes

try:  # seuils officiels du moteur, s'il les expose
    from src.detection_engine import RISK_THRESHOLDS as ENGINE_RISK_THRESHOLDS
except ImportError:
    ENGINE_RISK_THRESHOLDS = None

# ============================================================
# CONFIGURATION
# ============================================================

APP_NAME = "PhishGuard SOC"
APP_VERSION = "2.0.0"

BASE_DIR = Path(__file__).resolve().parent
SAMPLE_PATH = BASE_DIR / "samples" / "suspicious_email.eml"

MAX_UPLOAD_BYTES = 5 * 1024 * 1024      # 5 Mo
MAX_BODY_ANALYSIS = 200_000             # caractères scannés pour les IOC
MAX_BODY_DISPLAY = 20_000               # caractères affichés
MAX_FIELD_LEN = 1_000
MAX_EVIDENCE_LEN = 3_000
MAX_FINDINGS = 200
MAX_IOCS = 150

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_ICON = {
    "CRITICAL": "🟥",
    "HIGH": "🟧",
    "MEDIUM": "🟨",
    "LOW": "🟩",
    "INFO": "🟦",
}
LEVEL_COLOR = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#22c55e",
}
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
}

AUTH_METHODS = {
    "spf": ("SPF", "Le serveur d'envoi est-il autorisé par le domaine ?"),
    "dkim": ("DKIM", "La signature cryptographique du message est-elle valide ?"),
    "dmarc": ("DMARC", "Le message respecte-t-il la politique du domaine ?"),
}
AUTH_STATUS_LABEL = {
    "pass": "réussi",
    "fail": "échec",
    "softfail": "échec partiel",
    "permerror": "erreur permanente",
    "temperror": "erreur temporaire",
    "neutral": "neutre",
    "none": "aucun résultat",
    "policy": "politique locale",
    "unknown": "inconnu",
}
AUTH_BAD = {"fail", "softfail", "permerror", "temperror"}

MAX_AUTH_HEADERS = 20
TRUSTED_AUTHSERV_ENV = "PHISHGUARD_TRUSTED_AUTHSERV_IDS"
AUTHSERV_RE = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$")
AUTH_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
HEADER_FROM_RE = re.compile(r"\bheader\.from\s*=\s*([^\s;]+)", re.IGNORECASE)
STRUCT_HEADERS = ("from", "to", "subject", "date", "message-id", "received", "return-path")

# Utilisés uniquement si le moteur n'expose pas RISK_THRESHOLDS :
# à aligner sur detection_engine.py.
FALLBACK_RISK_THRESHOLDS = (("CRITICAL", 80), ("HIGH", 60), ("MEDIUM", 30))

# Regex volontairement simples et bornées (pas de backtracking catastrophique).
URL_RE = re.compile(r"https?://[^\s<>\"'()\[\]{}]{1,2048}", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EML_HEADER_RE = re.compile(
    r"^(from|to|subject|date|received|message-id|mime-version|return-path):",
    re.IGNORECASE | re.MULTILINE,
)
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
BIDI_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("phishguard")

# ============================================================
# PAGE
# ============================================================

st.set_page_config(
    page_title=APP_NAME,
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# CSS statique uniquement : aucune donnée utilisateur n'y est injectée.
STATIC_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap');

html, body, .stApp, [class*="css"] { font-family: 'IBM Plex Sans', system-ui, sans-serif; }
code, pre, .mono { font-family: 'IBM Plex Mono', ui-monospace, monospace !important; }

.stApp { background: #0a0f1c; color: #e2e8f0; }
section[data-testid="stSidebar"] { background: #0f1626; border-right: 1px solid #1c2740; }
h1, h2, h3 { color: #f1f5f9; letter-spacing: -0.01em; }
.block-container { padding-top: 2rem; max-width: 1240px; }

div[data-testid="stMetric"] {
    background: #111a2e; padding: 16px 18px; border-radius: 10px;
    border: 1px solid #1f2c47;
}
button[data-baseweb="tab"] { font-weight: 500; }

.risk-card {
    display: flex; align-items: center; gap: 28px;
    background: #111a2e; border: 1px solid #1f2c47; border-left: 4px solid var(--accent);
    border-radius: 12px; padding: 22px 26px;
}
.gauge {
    --size: 128px;
    width: var(--size); height: var(--size); border-radius: 50%; flex: none;
    background: conic-gradient(var(--accent) calc(var(--pct) * 1%), #1e293b 0);
    display: grid; place-items: center; position: relative;
}
.gauge::before {
    content: ""; position: absolute; inset: 11px; border-radius: 50%; background: #111a2e;
}
.gauge span { position: relative; font-size: 2.3rem; font-weight: 600; color: #f8fafc; }
.gauge small { position: relative; display: block; font-size: .7rem; color: #94a3b8; margin-top: -6px; }
.risk-level { font-size: 1.7rem; font-weight: 600; color: var(--accent); line-height: 1.1; }
.risk-note { color: #94a3b8; margin-top: 6px; max-width: 46ch; line-height: 1.5; }

.pill {
    display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: .78rem;
    border: 1px solid #2a3a5c; color: #cbd5e1; margin-right: 6px;
}
@media (max-width: 640px) { .risk-card { flex-direction: column; align-items: flex-start; } }
@media (prefers-reduced-motion: reduce) { * { transition: none !important; animation: none !important; } }
</style>
"""
st.markdown(STATIC_CSS, unsafe_allow_html=True)


# ============================================================
# ASSAINISSEMENT & AFFICHAGE SÛR
# ============================================================

def clean(value: Any, limit: int = MAX_FIELD_LEN) -> str:
    """Convertit en texte sûr : sans caractères de contrôle ni bidi, tronqué."""
    text = "" if value is None else str(value)
    text = CONTROL_RE.sub("", text)
    text = BIDI_RE.sub("", text)
    if len(text) > limit:
        text = text[:limit] + " … [tronqué]"
    return text


def defang_url(url: str) -> str:
    url = re.sub(r"^http", "hxxp", url, flags=re.IGNORECASE)
    return url.replace(".", "[.]")


def defang_text(text: str) -> str:
    return URL_RE.sub(lambda m: defang_url(m.group(0)), text)


def make_display(defang: bool) -> Callable[[str], str]:
    return defang_text if defang else (lambda s: s)


def to_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def clamp(value: int, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, value))


# ============================================================
# VALIDATION DU FICHIER
# ============================================================

class InvalidEmailFile(ValueError):
    """Fichier rejeté avant analyse."""


def validate_eml(name: str, data: bytes) -> None:
    if not name.lower().endswith(".eml"):
        raise InvalidEmailFile("Seuls les fichiers .eml sont acceptés.")
    if not data:
        raise InvalidEmailFile("Le fichier est vide.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise InvalidEmailFile(
            f"Fichier trop volumineux (maximum {MAX_UPLOAD_BYTES // (1024 * 1024)} Mo)."
        )
    head = data[:8192].decode("latin-1", errors="replace")
    if not EML_HEADER_RE.search(head):
        raise InvalidEmailFile(
            "Le contenu ne ressemble pas à un e-mail (aucun en-tête reconnu)."
        )


# ============================================================
# NORMALISATION DES DONNÉES (parser + moteur)
# ============================================================

def normalize_email(raw: Mapping[str, Any], auth_headers: Sequence[str] = ()) -> dict[str, Any]:
    """`auth_headers` ne doit contenir que des en-têtes Authentication-Results de confiance."""
    get = raw.get if isinstance(raw, Mapping) else (lambda k, d=None: d)
    return {
        "from": clean(get("from"), 500),
        "reply_to": clean(get("reply_to"), 500),
        "subject": clean(get("subject"), 500),
        "date": clean(get("date"), 200),
        "body": clean(get("body"), MAX_BODY_ANALYSIS),
        "authentication_results": [
            clean(h, 2000) for h in list(auth_headers)[:MAX_AUTH_HEADERS]
        ],
    }


def load_risk_thresholds() -> tuple[tuple[str, int], ...]:
    """Seuils du moteur si disponibles (liste de paires ou dict), sinon valeurs de repli."""
    candidate = ENGINE_RISK_THRESHOLDS
    try:
        pairs = list(candidate.items()) if isinstance(candidate, Mapping) else list(candidate or [])
        parsed = sorted(
            ((str(level).upper(), int(minimum)) for level, minimum in pairs
             if str(level).upper() in LEVEL_COLOR),
            key=lambda item: -item[1],
        )
        if parsed:
            return tuple(parsed)
    except (TypeError, ValueError):
        log.warning("RISK_THRESHOLDS du moteur illisibles, seuils de repli utilisés.")
    return FALLBACK_RISK_THRESHOLDS


RISK_THRESHOLDS = load_risk_thresholds()


def derive_level(score: int) -> str:
    for level, minimum in RISK_THRESHOLDS:
        if score >= minimum:
            return level
    return "LOW"


def normalize_result(raw: Mapping[str, Any], auth: dict[str, str]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for item in list(raw.get("findings") or [])[:MAX_FINDINGS]:
        if not isinstance(item, Mapping):
            continue
        severity = clean(item.get("severity"), 20).upper()
        findings.append({
            "type": clean(item.get("type"), 150) or "Indicateur",
            "severity": severity if severity in SEVERITY_ORDER else "INFO",
            "description": clean(item.get("description"), 2000),
            "evidence": clean(item.get("evidence"), MAX_EVIDENCE_LEN),
            "score": to_int(item.get("score")),
        })

    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]), -f["score"]))
    score = clamp(to_int(raw.get("risk_score")))
    level = derive_level(score)
    return {
        "risk_score": score,
        "risk_level": level,
        "total_findings": len(findings),
        "findings": findings,
        "authentication": auth,
    }


# ============================================================
# INDICATEURS DE COMPROMISSION (IOC)
# ============================================================

def extract_iocs(body: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for match in URL_RE.finditer(body):
        url = match.group(0).rstrip(".,;:!?")
        key = ("URL", url)
        if key in seen:
            continue
        seen.add(key)

        flags: list[str] = []
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
        except ValueError:
            host, parsed = "", None
            flags.append("URL malformée")

        if parsed is not None:
            if parsed.scheme == "http":
                flags.append("HTTP non chiffré")
            if parsed.username or "@" in parsed.netloc:
                flags.append("identifiants dans l'URL")
            if host.startswith("xn--") or ".xn--" in host:
                flags.append("domaine punycode")
            if host in URL_SHORTENERS:
                flags.append("raccourcisseur")
            try:
                ipaddress.ip_address(host)
                flags.append("hôte = adresse IP")
            except ValueError:
                pass
            if parsed.port and parsed.port not in (80, 443):
                flags.append(f"port atypique {parsed.port}")

        rows.append({"Type": "URL", "Valeur": url, "Alertes": ", ".join(flags) or "—"})
        if len(rows) >= MAX_IOCS:
            return rows

    for match in IPV4_RE.finditer(body):
        ip = match.group(0)
        key = ("IP", ip)
        if key in seen:
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        seen.add(key)
        scope = "privée" if addr.is_private else "publique"
        rows.append({"Type": "IP", "Valeur": ip, "Alertes": f"adresse {scope}"})
        if len(rows) >= MAX_IOCS:
            break
    return rows


def domain_of(address: str) -> str:
    _, addr = parseaddr(address)
    return addr.rsplit("@", 1)[-1].lower().strip() if "@" in addr else ""


def header_checks(email: Mapping[str, str]) -> list[str]:
    notes: list[str] = []
    sender_dom = domain_of(email["from"])
    reply_dom = domain_of(email["reply_to"])
    if reply_dom and sender_dom and reply_dom != sender_dom:
        notes.append(
            f"Le domaine de réponse ({reply_dom}) diffère de celui de l'expéditeur ({sender_dom})."
        )
    if not sender_dom:
        notes.append("Adresse d'expéditeur absente ou illisible.")
    if sender_dom.startswith("xn--") or ".xn--" in sender_dom:
        notes.append("Le domaine de l'expéditeur utilise du punycode (risque d'homographe).")
    return notes


# ============================================================
# ANALYSE (mise en cache par contenu, jamais par nom de fichier)
# ============================================================

def validate_structure(data: bytes) -> None:
    """Contrôle la structure RFC 5322 avec le parser standard, indépendamment de notre parser."""
    try:
        msg = BytesParser(policy=policy.default).parsebytes(data, headersonly=True)
        present = sum(1 for name in STRUCT_HEADERS if msg.get(name) is not None)
        has_from = msg.get("from") is not None
    except Exception as exc:  # noqa: BLE001
        raise InvalidEmailFile("Structure de l'e-mail illisible.") from exc
    if not has_from or present < 3:
        raise InvalidEmailFile(
            "Structure d'e-mail invalide : l'en-tête From et au moins deux autres en-têtes sont requis."
        )


def parse_trusted_ids(text: str) -> tuple[str, ...]:
    ids: list[str] = []
    for part in re.split(r"[,\s;]+", text.lower()):
        if part and AUTHSERV_RE.match(part) and part not in ids:
            ids.append(part)
    return tuple(ids[:20])


def extract_auth_headers(data: bytes) -> list[str]:
    """Lit les Authentication-Results depuis les octets bruts (ordre haut -> bas conservé)."""
    try:
        msg = BytesParser(policy=policy.default).parsebytes(data, headersonly=True)
        values = msg.get_all("Authentication-Results") or []
        return [clean(" ".join(str(v).split()), 2000) for v in values[:MAX_AUTH_HEADERS]]
    except Exception:  # noqa: BLE001
        log.warning("Lecture des en-têtes Authentication-Results impossible.")
        return []


def authserv_id(header: str) -> str:
    first = header.split(";", 1)[0].strip().split()
    return first[0].lower() if first else ""


def parse_auth_methods(header: str) -> dict[str, str]:
    """Extrait spf/dkim/dmarc en ignorant les commentaires et chaînes entre guillemets."""
    text = re.sub(r'"[^"]*"', " ", header)
    text = re.sub(r"\([^)]*\)", " ", text)
    found: dict[str, str] = {}
    for method, status in AUTH_RESULT_RE.findall(text):
        found.setdefault(method.lower(), status.lower())
    return found


def evaluate_auth_trust(
    headers: Sequence[str], trusted_ids: Sequence[str], sender_domain: str
) -> dict[str, Any]:
    """
    Authentication-Results peut être forgé par l'expéditeur. Règles appliquées :
      1. seuls les en-têtes dont l'authserv-id est approuvé sont retenus ;
      2. seul le plus haut (ajouté en dernier par votre MTA) est utilisé ; un autre
         en-tête portant le même authserv-id est considéré comme une falsification ;
      3. sans authserv-id configuré, rien n'est considéré comme fiable.
    """
    trusted_headers: list[str] = []
    ignored_ids: list[str] = []
    claimed = {m: "unknown" for m in AUTH_METHODS}
    untrusted_claims = {m: "unknown" for m in AUTH_METHODS}
    duplicates = 0

    for header in headers:
        sid = authserv_id(header)
        methods = {m: v for m, v in parse_auth_methods(header).items() if v in AUTH_STATUS_LABEL}
        for method, status in methods.items():
            if claimed[method] == "unknown":
                claimed[method] = status

        if sid and sid in trusted_ids and not trusted_headers:
            trusted_headers.append(header)
            continue

        for method, status in methods.items():
            if untrusted_claims[method] == "unknown":
                untrusted_claims[method] = status
        if sid and sid in trusted_ids:
            duplicates += 1
        else:
            ignored_ids.append(sid or "(vide)")

    auth = {m: "unknown" for m in AUTH_METHODS}
    notes: list[str] = []

    if not trusted_ids:
        mode = "unconfigured"
        notes.append(
            "Aucun authserv-id de confiance n'est configuré : les résultats déclarés "
            "par l'e-mail ne sont pas pris en compte."
        )
    elif not trusted_headers:
        mode = "missing"
        notes.append(
            "Aucun Authentication-Results ajouté par un serveur de confiance n'a été trouvé."
        )
    else:
        mode = "verified"
        for method, status in parse_auth_methods(trusted_headers[0]).items():
            if status in AUTH_STATUS_LABEL:
                auth[method] = status

        match = HEADER_FROM_RE.search(trusted_headers[0])
        if match and sender_domain:
            header_from = match.group(1).strip('"<>;').lower()
            related = (
                sender_domain == header_from
                or sender_domain.endswith("." + header_from)
                or header_from.endswith("." + sender_domain)
            )
            if header_from and not related:
                notes.append(
                    f"header.from ({header_from}) ne correspond pas au domaine de l'expéditeur ({sender_domain})."
                )
        for method in AUTH_METHODS:
            if untrusted_claims[method] == "pass" and auth[method] != "pass":
                notes.append(
                    f"Un en-tête non fiable déclare {method.upper()}=pass alors que le serveur "
                    f"de confiance indique « {AUTH_STATUS_LABEL[auth[method]]} » : falsification probable."
                )

    if duplicates:
        notes.append(
            f"{duplicates} en-tête(s) supplémentaire(s) portent votre authserv-id : "
            "seul le plus récent est retenu, les autres sont probablement forgés."
        )
    if trusted_ids and ignored_ids:
        notes.append(
            "En-têtes ignorés (authserv-id non approuvé) : "
            + ", ".join(sorted(set(ignored_ids))[:5]) + "."
        )

    return {
        "mode": mode,
        "auth": auth,
        "trusted_headers": trusted_headers,
        "trusted_ids": list(trusted_ids),
        "ignored_ids": sorted(set(ignored_ids)),
        "claimed": claimed,
        "notes": notes,
    }


@st.cache_data(show_spinner=False, max_entries=16, ttl=3600)
def run_analysis(data: bytes, trusted_ids: tuple[str, ...]) -> dict[str, Any]:
    validate_structure(data)
    raw = parse_email_bytes(data)

    sender = clean(raw.get("from"), 500) if isinstance(raw, Mapping) else ""
    trust = evaluate_auth_trust(extract_auth_headers(data), trusted_ids, domain_of(sender))

    # Le moteur ne reçoit que les en-têtes de confiance, jamais ceux de l'expéditeur.
    email = normalize_email(raw, trust["trusted_headers"])
    if not (email["from"] or email["subject"] or email["body"]):
        raise InvalidEmailFile("Le parser n'a extrait aucun contenu exploitable.")

    result = normalize_result(analyze_email(email), trust["auth"])
    return {
        "email": email,
        "result": result,
        "iocs": extract_iocs(email["body"]),
        "header_notes": header_checks(email),
        "auth_trust": {
            key: trust[key]
            for key in ("mode", "trusted_ids", "ignored_ids", "claimed", "notes")
        },
    }


def load_source(source: str, uploaded) -> tuple[bytes | None, str]:
    """Retourne (octets, nom) de l'e-mail à analyser, ou (None, '')."""
    if source == "E-mail d'exemple":
        sample = SAMPLE_PATH.resolve()
        if not sample.is_file() or BASE_DIR not in sample.parents:
            st.error("E-mail d'exemple introuvable.")
            return None, ""
        return sample.read_bytes(), sample.name
    if uploaded is None:
        return None, ""
    data = uploaded.getvalue()
    validate_eml(uploaded.name, data)
    return data, "upload.eml"


# ============================================================
# COMPOSANTS D'INTERFACE
# ============================================================

def risk_card(score: int, level: str) -> None:
    notes = {
        "CRITICAL": "Plusieurs indicateurs forts. Ne pas interagir avec ce message et l'escalader immédiatement.",
        "HIGH": "Message très probablement malveillant. Isoler et enquêter avant toute action.",
        "MEDIUM": "Indicateurs suspects. Une vérification manuelle est nécessaire.",
        "LOW": "Aucun indicateur fort. Cela ne garantit pas que le message soit légitime.",
    }
    # Seules des valeurs issues de listes blanches ou d'entiers bornés sont injectées.
    score = clamp(to_int(raw.get("risk_score")))
    level = derive_level(score)
    st.markdown(
        f"""
        <div class="risk-card" style="--accent:{color}; --pct:{int(score)};">
            <div class="gauge"><div><span>{int(score)}</span><small>sur 100</small></div></div>
            <div>
                <div class="risk-level">Niveau {html.escape(level.lower())}</div>
                <div class="risk-note">{html.escape(notes[level])}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_overview(data: dict[str, Any], show: Callable[[str], str]) -> None:
    email, result = data["email"], data["result"]
    risk_card(result["risk_score"], result["risk_level"])
    st.write("")

    c1, c2, c3 = st.columns(3)
    c1.metric("Score de risque", f'{result["risk_score"]}/100')
    c2.metric("Constats", result["total_findings"])
    c3.metric("Indicateurs extraits", len(data["iocs"]))

    st.write("")
    left, right = st.columns([3, 2], gap="large")

    with left:
        st.subheader("Message")
        st.caption("Expéditeur")
        st.code(show(email["from"]) or "Inconnu", language=None)
        st.caption("Adresse de réponse")
        st.code(show(email["reply_to"]) or "Non renseignée", language=None)
        st.caption("Objet")
        st.code(show(email["subject"]) or "Sans objet", language=None)
        st.caption("Date")
        st.text(email["date"] or "Inconnue")

    with right:
        st.subheader("Répartition")
        counts = Counter(f["severity"] for f in result["findings"])
        if counts:
            chart = {s: counts[s] for s in SEVERITY_ORDER if counts[s]}
            st.bar_chart(chart, horizontal=True)
        else:
            st.success("Aucun constat à répartir.")

        if data["header_notes"]:
            st.subheader("Contrôles d'en-têtes")
            for note in data["header_notes"]:
                st.warning(note)


def render_authentication(auth: dict[str, str], trust: dict[str, Any]) -> None:
    st.subheader("Authentification de l'expéditeur")

    verified = trust["mode"] == "verified"
    passed = sum(status == "pass" for status in auth.values())
    failed = sum(status in AUTH_BAD for status in auth.values())

    if not verified:
        st.warning(
            "Authentification non vérifiable : sans en-tête d'un serveur de confiance, "
            "SPF, DKIM et DMARC restent à « inconnu »."
        )
    elif failed:
        st.error("Au moins un contrôle a échoué : l'expéditeur a pu être usurpé.")
    elif passed == len(auth):
        st.success("SPF, DKIM et DMARC sont validés par votre serveur de confiance.")
    else:
        st.warning("Authentification incomplète : au moins un contrôle est absent ou inconnu.")

    st.write("")
    columns = st.columns(len(AUTH_METHODS))
    for column, (key, (label, hint)) in zip(columns, AUTH_METHODS.items()):
        status = auth[key]
        text = f"{label} : {AUTH_STATUS_LABEL[status]}"
        with column:
            if status == "pass":
                st.success(text, icon="✅")
            elif status in AUTH_BAD:
                st.error(text, icon="⛔")
            else:
                st.warning(text, icon="⚠️")
            st.caption(hint)

    if verified:
        st.metric("Contrôles réussis", f"{passed}/{len(auth)}")

    for note in trust["notes"]:
        st.warning(note)

    with st.expander("Valeurs déclarées dans l'e-mail (non fiables)"):
        st.caption("Ces valeurs peuvent être forgées par l'expéditeur. Elles ne servent pas au score.")
        st.code(
            "\n".join(f"{name}={value}" for name, value in trust["claimed"].items()),
            language=None,
        )

    st.caption(
        "Un résultat « réussi » ne prouve pas que le message est légitime : "
        "un attaquant peut authentifier correctement son propre domaine."
    )


def render_findings(result: dict[str, Any], show: Callable[[str], str]) -> None:
    findings = result["findings"]
    if not findings:
        st.success("Aucun indicateur suspect détecté.")
        return

    available = [s for s in SEVERITY_ORDER if any(f["severity"] == s for f in findings)]
    chosen = st.multiselect("Filtrer par sévérité", available, default=available)
    st.caption(f"{sum(f['severity'] in chosen for f in findings)} constat(s) affiché(s) sur {len(findings)}.")

    for index, finding in enumerate(findings, start=1):
        if finding["severity"] not in chosen:
            continue
        icon = SEVERITY_ICON[finding["severity"]]
        title = f'{icon} {index}. {finding["type"]} · {finding["severity"].lower()} · +{finding["score"]}'
        with st.expander(title, expanded=finding["severity"] in ("CRITICAL", "HIGH")):
            # st.text : aucun rendu Markdown, donc aucun lien ni image distante.
            st.text(finding["description"] or "Aucune description.")
            if finding["evidence"]:
                st.caption("Preuve")
                st.code(show(finding["evidence"]), language=None)


def render_iocs(iocs: list[dict[str, str]], show: Callable[[str], str]) -> None:
    if not iocs:
        st.info("Aucun indicateur (URL ou adresse IP) trouvé dans le corps du message.")
        return
    rows = [{**row, "Valeur": show(row["Valeur"])} for row in iocs]
    st.dataframe(rows, hide_index=True)
    if len(iocs) >= MAX_IOCS:
        st.caption(f"Liste limitée aux {MAX_IOCS} premiers indicateurs.")
    st.caption("Les liens ne sont jamais cliquables dans cette interface.")


def render_content(email: dict[str, str], show: Callable[[str], str]) -> None:
    st.caption("Le contenu est affiché en texte brut, sans exécution ni chargement de ressources.")
    body = email["body"]
    shown = body[:MAX_BODY_DISPLAY]
    with st.expander("Corps du message", expanded=False):
        st.code(show(shown) or "(vide)", language=None)
        if len(body) > MAX_BODY_DISPLAY:
            st.caption(f"Affichage limité à {MAX_BODY_DISPLAY:,} caractères.".replace(",", " "))


def build_report(data: dict[str, Any], sha256: str) -> str:
    email, result = data["email"], data["result"]
    report = {
        "tool": f"{APP_NAME} {APP_VERSION}",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "evidence_sha256": sha256,
        "message": {
            "from": defang_text(email["from"]),
            "reply_to": defang_text(email["reply_to"]),
            "subject": defang_text(email["subject"]),
            "date": email["date"],
        },
        "assessment": {
            "risk_score": result["risk_score"],
            "risk_level": result["risk_level"],
            "total_findings": result["total_findings"],
        },
        "authentication": {
            "results": result["authentication"],
            "trust_mode": data["auth_trust"]["mode"],
            "trusted_authserv_ids": data["auth_trust"]["trusted_ids"],
            "notes": data["auth_trust"]["notes"],
        },
        "header_notes": data["header_notes"],
        "findings": [
            {**f, "evidence": defang_text(f["evidence"])} for f in result["findings"]
        ],
        "indicators": [{**r, "Valeur": defang_text(r["Valeur"])} for r in data["iocs"]],
    }
    return json.dumps(report, ensure_ascii=False, indent=2)


# ============================================================
# EN-TÊTE & BARRE LATÉRALE
# ============================================================

st.title("🛡️ PhishGuard SOC")
st.caption("Détection et investigation d'e-mails de phishing")

with st.sidebar:
    st.header("Investigation")
    source = st.radio("Source de l'e-mail", ["E-mail d'exemple", "Importer un e-mail"])

    uploaded = None
    if source == "Importer un e-mail":
        uploaded = st.file_uploader(
            "Fichier .eml",
            type=["eml"],
            help=f"Taille maximale : {MAX_UPLOAD_BYTES // (1024 * 1024)} Mo. Le fichier reste en mémoire.",
        )

    st.divider()
    defang = st.toggle(
        "Défanger les liens",
        value=True,
        help="Remplace http par hxxp et les points par [.] pour éviter un clic accidentel.",
    )
    trusted_input = st.text_input(
        "authserv-id de confiance",
        value=os.environ.get(TRUSTED_AUTHSERV_ENV, ""),
        max_chars=500,
        placeholder="mx.votre-entreprise.com",
        help=(
            "Nom du serveur de réception qui ajoute Authentication-Results "
            "(plusieurs valeurs séparées par des virgules). Sans cette valeur, "
            "SPF/DKIM/DMARC ne sont pas considérés comme fiables."
        ),
    )
    st.caption("Conseil : analysez les e-mails suspects depuis un poste isolé.")

show = make_display(defang)
trusted_ids = parse_trusted_ids(trusted_input)

# ============================================================
# FLUX PRINCIPAL
# ============================================================

try:
    raw_bytes, _ = load_source(source, uploaded)
except InvalidEmailFile as error:
    st.error(str(error))
    st.stop()

if raw_bytes is None:
    st.info("Choisissez l'e-mail d'exemple ou importez un fichier .eml pour démarrer.")
    st.stop()

sha256 = hashlib.sha256(raw_bytes).hexdigest()

try:
    with st.spinner("Analyse en cours…"):
        analysis = run_analysis(raw_bytes, trusted_ids)
except InvalidEmailFile as error:
    st.error(str(error))
    st.stop()
except Exception:  # noqa: BLE001 — le détail technique reste dans les logs
    log.exception("Échec de l'analyse (sha256=%s)", sha256)
    st.error("Impossible d'analyser ce fichier. Vérifiez qu'il s'agit d'un e-mail .eml valide.")
    st.stop()

log.info(
    "Analyse terminée sha256=%s score=%s niveau=%s",
    sha256[:12], analysis["result"]["risk_score"], analysis["result"]["risk_level"],
)

tab_overview, tab_auth, tab_findings, tab_iocs, tab_content, tab_report = st.tabs(
    ["Synthèse", "Authentification", "Constats", "Indicateurs", "Contenu", "Rapport"]
)

with tab_overview:
    render_overview(analysis, show)

with tab_auth:
    render_authentication(analysis["result"]["authentication"], analysis["auth_trust"])

with tab_findings:
    render_findings(analysis["result"], show)

with tab_iocs:
    render_iocs(analysis["iocs"], show)

with tab_content:
    render_content(analysis["email"], show)

with tab_report:
    st.subheader("Rapport d'investigation")
    st.caption("Empreinte SHA-256 du fichier analysé")
    st.code(sha256, language=None)
    st.download_button(
        "Télécharger le rapport (JSON)",
        data=build_report(analysis, sha256),
        file_name=f"phishguard_{sha256[:12]}.json",
        mime="application/json",
    )
    st.caption("Les liens du rapport sont défangés. Aucun fichier n'est conservé sur le serveur.")

st.divider()
st.caption(f"{APP_NAME} {APP_VERSION} · Outil pédagogique d'investigation")