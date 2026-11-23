import hashlib

from src.attachment_analyzer import (
    analyze_attachment,
    analyze_attachments,
)


def test_detect_executable_attachment():
    result = analyze_attachment({
        "filename": "invoice.exe",
        "content_type": "application/octet-stream",
        "content": b"fake executable",
    })

    assert any(
        finding["type"] == "DANGEROUS_ATTACHMENT"
        for finding in result["findings"]
    )


def test_detect_double_extension():
    result = analyze_attachment({
        "filename": "invoice.pdf.exe",
        "content_type": "application/octet-stream",
        "content": b"test",
    })

    types = {
        finding["type"]
        for finding in result["findings"]
    }

    assert "DOUBLE_EXTENSION_ATTACHMENT" in types


def test_detect_macro_enabled_document():
    result = analyze_attachment({
        "filename": "report.docm",
        "content_type": "application/octet-stream",
        "content": b"test",
    })

    assert any(
        finding["type"] == "MACRO_ENABLED_ATTACHMENT"
        for finding in result["findings"]
    )


def test_detect_mime_mismatch():
    result = analyze_attachment({
        "filename": "report.pdf",
        "content_type": "text/plain",
        "content": b"test",
    })

    assert any(
        finding["type"] == "ATTACHMENT_MIME_MISMATCH"
        for finding in result["findings"]
    )


def test_calculate_sha256():
    content = b"safe test content"

    result = analyze_attachment({
        "filename": "notes.txt",
        "content_type": "text/plain",
        "content": content,
    })

    assert result["sha256"] == hashlib.sha256(content).hexdigest()


def test_empty_attachment_list():
    assert analyze_attachments([]) == []


def test_multiple_attachments():
    attachments = [
        {
            "filename": "notes.txt",
            "content_type": "text/plain",
            "content": b"hello",
        },
        {
            "filename": "payload.exe",
            "content_type": "application/octet-stream",
            "content": b"test",
        },
    ]

    results = analyze_attachments(attachments)

    assert len(results) == 2
    assert results[0]["filename"] == "notes.txt"
    assert results[1]["filename"] == "payload.exe"


def test_invalid_content_type():
    try:
        analyze_attachment({
            "filename": "test.exe",
            "content_type": "application/octet-stream",
            "content": "not bytes",
        })
    except TypeError:
        return

    assert False, "Expected TypeError"
