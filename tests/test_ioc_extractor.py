import ast
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

import pytest


# Charger la vraie fonction depuis app.py sans exécuter Streamlit
APP_PATH = Path(__file__).resolve().parents[1] / "app.py"
tree = ast.parse(APP_PATH.read_text(encoding="utf-8"))

required_names = {
    "MAX_BODY_ANALYSIS",
    "MAX_IOCS",
    "URL_SHORTENERS",
    "URL_RE",
    "IPV4_RE",
    "DOMAIN_RE",
}

nodes = []

for node in tree.body:
    if isinstance(node, ast.Assign):
        names = {
            target.id
            for target in node.targets
            if isinstance(target, ast.Name)
        }
        if names & required_names:
            nodes.append(node)

    elif isinstance(node, ast.FunctionDef) and node.name == "extract_iocs":
        nodes.append(node)

namespace = {
    "ipaddress": ipaddress,
    "re": re,
    "urlparse": urlparse,
}

module = ast.Module(body=nodes, type_ignores=[])
exec(compile(ast.fix_missing_locations(module), str(APP_PATH), "exec"), namespace)

extract_iocs = namespace["extract_iocs"]


def test_extract_url():
    results = extract_iocs("Visit http://example.com/login")
    assert any(item["Type"] == "URL" for item in results)


def test_extract_ipv4():
    results = extract_iocs("Suspicious IP: 8.8.8.8")
    assert any(
        item["Type"] == "IP" and item["Valeur"] == "8.8.8.8"
        for item in results
    )


def test_extract_domain():
    results = extract_iocs("Domain: secure-account.click")
    assert any(
        item["Type"] == "DOMAIN"
        and item["Valeur"] == "secure-account.click"
        for item in results
    )


def test_duplicate_urls_are_removed():
    results = extract_iocs(
        "http://example.com http://example.com"
    )
    urls = [item["Valeur"] for item in results if item["Type"] == "URL"]
    assert urls.count("http://example.com") == 1


def test_invalid_ipv4_is_not_an_ip():
    results = extract_iocs("Invalid IP: 999.999.999.999")
    ips = [item["Valeur"] for item in results if item["Type"] == "IP"]
    assert "999.999.999.999" not in ips


def test_max_iocs_limit():
    text = " ".join(f"http://host{i}.com" for i in range(200))
    results = extract_iocs(text)
    assert len(results) <= namespace["MAX_IOCS"]


def test_body_analysis_limit():
    limit = namespace["MAX_BODY_ANALYSIS"]
    text = "A" * limit + " http://outside-limit.com"
    results = extract_iocs(text)
    assert not any(
        item["Valeur"] == "http://outside-limit.com"
        for item in results
    )


def test_private_ip_classification():
    results = extract_iocs("Private IP: 192.168.1.10")
    item = next(
        item for item in results
        if item["Type"] == "IP" and item["Valeur"] == "192.168.1.10"
    )
    assert item["Alertes"] == "adresse privée"


def test_reserved_ip_classification():
    results = extract_iocs("Test IP: 198.51.100.23")
    item = next(
        item for item in results
        if item["Type"] == "IP" and item["Valeur"] == "198.51.100.23"
    )
    assert item["Alertes"] == "adresse réservée / non publique"


def test_public_ip_classification():
    results = extract_iocs("Public IP: 8.8.8.8")
    item = next(
        item for item in results
        if item["Type"] == "IP" and item["Valeur"] == "8.8.8.8"
    )
    assert item["Alertes"] == "adresse publique"
