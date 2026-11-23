from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any


def extract_attachments(message: Any) -> list[dict[str, Any]]:
    """Extract attachment metadata without executing or opening files."""

    attachments = []

    for part in message.walk():
        if part.is_multipart():
            continue

        filename = part.get_filename()
        content_disposition = part.get_content_disposition()

        if not filename and content_disposition != "attachment":
            continue

        payload = part.get_payload(decode=True)

        if payload is None:
            payload = b""

        attachments.append({
            "filename": filename or "unnamed_attachment",
            "content_type": part.get_content_type().lower(),
            "size": len(payload),
            "content": payload,
        })

    return attachments


def parse_email_bytes(content: bytes) -> dict[str, Any]:
    message = BytesParser(
        policy=policy.default
    ).parsebytes(content)

    body_part = message.get_body(
        preferencelist=("plain",)
    )

    return {
        "from": message.get("From", ""),
        "reply_to": message.get("Reply-To", ""),
        "subject": message.get("Subject", ""),
        "date": message.get("Date", ""),
        "message_id": message.get("Message-ID", ""),
        "body": body_part.get_content() if body_part else "",
        "authentication_results": message.get_all(
            "Authentication-Results", []
        ),
        "attachments": extract_attachments(message),
    }


def parse_email(file_path: str | Path) -> dict[str, Any]:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Email file not found: {file_path}"
        )

    return parse_email_bytes(path.read_bytes())
