"""
tests/smtp_catcher.py — in-process aiosmtpd that captures messages.

Pure Python, no Docker. Binds 127.0.0.1 on an OS-assigned free port so
parallel xdist workers don't collide. Captured messages are parsed into
email.message.Message objects and (optionally) dumped as .eml for manual
eyeballing.
"""
from __future__ import annotations

import socket
from email import message_from_bytes
from email.message import Message
from pathlib import Path

from aiosmtpd.controller import Controller


def _free_port() -> int:
    """Ask the OS for a free TCP port on 127.0.0.1, then release the socket.

    aiosmtpd's Controller does not support port=0 on Windows because its
    internal _trigger_server() probe connects to self.port before the OS-assigned
    port is read back.  We pre-allocate here instead.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _CaptureHandler:
    def __init__(self, dump_dir: Path | None) -> None:
        self.messages: list[Message] = []
        self.dump_dir = dump_dir
        if dump_dir:
            dump_dir.mkdir(parents=True, exist_ok=True)

    async def handle_DATA(self, server, session, envelope):
        msg = message_from_bytes(envelope.content)
        self.messages.append(msg)
        if self.dump_dir:
            idx = len(self.messages)
            (self.dump_dir / f"message_{idx:03d}.eml").write_bytes(envelope.content)
        return "250 Message accepted for delivery"


class SmtpCatcher:
    """Context manager around an aiosmtpd Controller on a free local port."""

    def __init__(self, dump_dir: Path | None = None) -> None:
        self._handler = _CaptureHandler(dump_dir)
        # port=0 → OS assigns a free port, read back after start().
        self._port = _free_port()
        self._controller = Controller(self._handler, hostname="127.0.0.1", port=self._port)

    def __enter__(self) -> "SmtpCatcher":
        self._controller.start()
        return self

    def __exit__(self, *exc) -> None:
        self._controller.stop()

    @property
    def host(self) -> str:
        return self._controller.hostname

    @property
    def port(self) -> int:
        return self._controller.server.sockets[0].getsockname()[1]

    @property
    def messages(self) -> list[Message]:
        return self._handler.messages
