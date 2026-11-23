
from src.email_parser import parse_email_bytes


def test_parse_email_attachment():
    raw_email = (
        b"From: sender@example.com\r\n"
        b"To: receiver@example.com\r\n"
        b"Subject: Attachment test\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=test-boundary\r\n"
        b"\r\n"
        b"--test-boundary\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Please review the attachment.\r\n"
        b"--test-boundary\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename=invoice.exe\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
        b"SGVsbG8=\r\n"
        b"--test-boundary--\r\n"
    )

    email = parse_email_bytes(raw_email)

    assert len(email["attachments"]) == 1
    assert email["attachments"][0]["filename"] == "invoice.exe"
    assert email["attachments"][0]["content"] == b"Hello"
    assert email["attachments"][0]["size"] == 5