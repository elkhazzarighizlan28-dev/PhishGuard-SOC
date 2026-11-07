
from email import message, policy
from email.parser import BytesParser
from pathlib import Path


def parse_email_bytes(content):
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
}
    


def parse_email(file_path):
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Email file not found: {file_path}"
        )

    return parse_email_bytes(path.read_bytes())

