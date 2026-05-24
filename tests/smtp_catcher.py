"""
tests/smtp_catcher.py — capture outbound email by faking the smtplib transport.

WHY NOT A REAL IN-PROCESS SERVER:
delivery/email_sender.py forces ``ehlo(); starttls(); ehlo(); login(...)`` on
the plain path (and ``SMTP_SSL`` + ``login`` on the SSL path). A plain in-process
server (e.g. aiosmtpd) advertises neither STARTTLS nor AUTH, and the sender's
``starttls()`` is called with no SSL context — which uses a verifying default
context that rejects any self-signed test cert. So a real local server cannot
receive from this sender without defeating the very TLS/auth logic we want to
exercise.

INSTEAD: monkeypatch ``smtplib.SMTP`` / ``smtplib.SMTP_SSL`` with a fake transport
that records the raw bytes handed to ``sendmail()``. This runs ALL of
``send_report_email`` unchanged — MIME assembly, recipient validation,
attachment-size fallback, and the full ehlo/starttls/login/sendmail call
sequence — and captures exactly the bytes that would go on the wire. Captured
messages are parsed into ``email.message.Message`` and dumped as ``.eml`` for
manual eyeballing.
"""
from __future__ import annotations

import smtplib
from email import message_from_bytes
from email.message import Message
from pathlib import Path


class SmtpCapture:
    """Records messages sent through a faked smtplib transport."""

    def __init__(self, dump_dir: Path | None = None) -> None:
        self.messages: list[Message] = []
        self.sent: list[tuple] = []  # (from_addr, to_addrs) per send
        self.dump_dir = dump_dir

    def _record(self, from_addr, to_addrs, raw) -> None:
        data = raw if isinstance(raw, (bytes, bytearray)) else str(raw).encode("utf-8")
        data = bytes(data)
        self.messages.append(message_from_bytes(data))
        self.sent.append((from_addr, list(to_addrs) if to_addrs else []))
        if self.dump_dir:
            self.dump_dir.mkdir(parents=True, exist_ok=True)
            (self.dump_dir / f"message_{len(self.messages):03d}.eml").write_bytes(data)

    def install(self, monkeypatch) -> "SmtpCapture":
        """Patch smtplib.SMTP and smtplib.SMTP_SSL to route into this capture."""
        capture = self

        class _FakeSMTP:
            def __init__(self, host=None, port=0, timeout=None, *args, **kwargs):
                self.host, self.port = host, port

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def ehlo(self, *a, **k):
                return (250, b"mock-ehlo")

            def starttls(self, *a, **k):
                return (220, b"ready to start TLS")

            def login(self, *a, **k):
                return (235, b"authenticated")

            def sendmail(self, from_addr, to_addrs, msg, *a, **k):
                capture._record(from_addr, to_addrs, msg)
                return {}

            def send_message(self, msg, from_addr=None, to_addrs=None, *a, **k):
                capture._record(from_addr, to_addrs, msg.as_bytes())
                return {}

            def quit(self):
                return (221, b"bye")

            def close(self):
                pass

        monkeypatch.setattr(smtplib, "SMTP", _FakeSMTP)
        monkeypatch.setattr(smtplib, "SMTP_SSL", _FakeSMTP)
        return self
