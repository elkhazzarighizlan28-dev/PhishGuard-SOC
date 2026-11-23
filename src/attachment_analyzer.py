
import hashlib
from pathlib import PurePath
from typing import Any

from src.schemas import Finding


DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com",
    ".bat", ".cmd", ".ps1", ".vbs",
    ".vbe", ".js", ".jse", ".wsf",
    ".hta", ".msi", ".jar",
}

MACRO_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm",
}

DOCUMENT_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls",
    ".xlsx", ".ppt", ".pptx",
}

EXPECTED_MIME_TYPES = {
    ".pdf": {"application/pdf"},
    ".docx": {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    },
    ".xlsx": {
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    },
    ".pptx": {
        "application/vnd.openxmlformats-officedocument.presentationml.presentation"
    },
}


def analyze_attachment(
    attachment: dict[str, Any]
) -> dict[str, Any]:

    filename = str(
        attachment.get("filename") or "unnamed_attachment"
    )

    content = attachment.get("content", b"")

    if not isinstance(content, bytes):
        raise TypeError("Attachment content must be bytes.")

    content_type = str(
        attachment.get("content_type") or
        "application/octet-stream"
    ).lower()

    extension = PurePath(filename).suffix.lower()

    file_hash = hashlib.sha256(content).hexdigest()

    findings: list[Finding] = []

    suffixes = [
        suffix.lower()
        for suffix in PurePath(filename).suffixes
    ]

    # Detect dangerous file extensions.
    if extension in DANGEROUS_EXTENSIONS:
        findings.append(Finding(
            type="DANGEROUS_ATTACHMENT",
            severity="HIGH",
            description="Attachment uses a potentially dangerous file extension.",
            evidence=f"Filename: {filename} | Extension: {extension}",
            score=35,
        ))

    # Detect macro-enabled Office documents.
    if extension in MACRO_EXTENSIONS:
        findings.append(Finding(
            type="MACRO_ENABLED_ATTACHMENT",
            severity="HIGH",
            description="Attachment uses a macro-enabled Office extension.",
            evidence=f"Filename: {filename}",
            score=30,
        ))

    # Detect misleading double extensions.
    if len(suffixes) >= 2:
        previous_extension = suffixes[-2]

        if (
            previous_extension in DOCUMENT_EXTENSIONS
            and extension in DANGEROUS_EXTENSIONS
        ):
            findings.append(Finding(
                type="DOUBLE_EXTENSION_ATTACHMENT",
                severity="HIGH",
                description="Attachment has a document extension followed by an executable extension.",
                evidence=f"Filename: {filename}",
                score=35,
            ))

    # Detect MIME type inconsistencies for known document formats.
    expected_types = EXPECTED_MIME_TYPES.get(extension)

    if (
        expected_types
        and content_type not in expected_types
    ):
        findings.append(Finding(
            type="ATTACHMENT_MIME_MISMATCH",
            severity="MEDIUM",
            description="Attachment MIME type does not match its filename extension.",
            evidence=(
                f"Filename: {filename} | "
                f"Declared MIME: {content_type}"
            ),
            score=20,
        ))

    return {
        "filename": filename,
        "extension": extension,
        "content_type": content_type,
        "size": len(content),
        "sha256": file_hash,
        "findings": [
            finding.to_dict()
            for finding in findings
        ],
    }


def analyze_attachments(
    attachments: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Analyze metadata and hashes for all email attachments."""

    return [
        analyze_attachment(attachment)
        for attachment in attachments
    ]
