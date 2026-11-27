from src.received_analyzer import SLOW_HOP_SECONDS, analyze_received


def make_eml(*received: str) -> bytes:
    """Les en-têtes Received sont donnés du plus récent (haut) au plus ancien (bas)."""
    lines = [f"Received: {value}" for value in received]
    lines += ["From: a@example.com", "To: b@example.org", "Subject: Test", "", "Body", ""]
    return "\r\n".join(lines).encode()


THREE_HOPS = make_eml(
    "from mx.example.com (mx [8.8.4.4]) by mail.victim.com; Fri, 27 Nov 2026 10:05:00 +0000",
    "from relay.example.net ([1.1.1.1]) by mx.example.com; Fri, 27 Nov 2026 10:00:00 +0000",
    "from [10.0.0.5] (unknown) by relay.example.net; Fri, 27 Nov 2026 09:59:30 +0000",
)


def test_hops_are_in_chronological_order():
    result = analyze_received(THREE_HOPS)

    assert [hop["hop"] for hop in result["hops"]] == [1, 2, 3]
    assert result["hops"][0]["by"] == "relay.example.net"
    assert result["hops"][2]["by"] == "mail.victim.com"


def test_delays_between_hops():
    result = analyze_received(THREE_HOPS)

    assert result["hops"][0]["delay_s"] is None
    assert result["hops"][1]["delay_s"] == 30
    assert result["hops"][2]["delay_s"] == 300
    assert result["total_delay_s"] == 330


def test_origin_ip_is_first_public_address():
    result = analyze_received(THREE_HOPS)

    # 10.0.0.5 est privée : la première IP publique rencontrée est 1.1.1.1.
    assert result["origin_ip"] == "1.1.1.1"
    assert result["hops"][0]["ips"] == ["10.0.0.5"]


def test_negative_delay_is_flagged():
    eml = make_eml(
        "from a (a [8.8.8.8]) by b; Fri, 27 Nov 2026 09:00:00 +0000",
        "from c (c [1.1.1.1]) by a; Fri, 27 Nov 2026 10:00:00 +0000",
    )

    result = analyze_received(eml)

    assert "délai négatif" in result["hops"][1]["flags"]
    assert any("incohérents" in note for note in result["notes"])


def test_slow_hop_is_flagged():
    eml = make_eml(
        "from a (a [8.8.8.8]) by b; Fri, 27 Nov 2026 12:00:00 +0000",
        "from c (c [1.1.1.1]) by a; Fri, 27 Nov 2026 10:00:00 +0000",
    )

    result = analyze_received(eml)

    assert result["hops"][1]["delay_s"] == 7200
    assert result["hops"][1]["delay_s"] > SLOW_HOP_SECONDS
    assert "délai > 1 h" in result["hops"][1]["flags"]


def test_unreadable_date_is_flagged():
    eml = make_eml("from a (a [8.8.8.8]) by b; pas une date")

    result = analyze_received(eml)

    assert "date illisible" in result["hops"][0]["flags"]
    assert result["total_delay_s"] is None


def test_no_received_header():
    result = analyze_received(make_eml())

    assert result["hops"] == []
    assert result["origin_ip"] == ""
    assert result["notes"]


def test_garbage_input_does_not_crash():
    result = analyze_received(b"\x00\xff not an email")

    assert result["hops"] == []