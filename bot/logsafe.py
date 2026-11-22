"""Keep credentials out of log files.

`requests` exceptions embed the full request URL, and Telegram's URL contains the bot token
(``/bot<TOKEN>/getUpdates``), so an ordinary network error would otherwise write the token to disk.
"""
from __future__ import annotations

import logging
import re

_BOT_URL = re.compile(r"/(file/)?bot\d+:[A-Za-z0-9_-]{20,}")
_TOKEN = re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{30,45}\b")
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}")


class RedactFilter(logging.Filter):
    def __init__(self, secrets=()):
        super().__init__()
        self.secrets = sorted({s for s in secrets if s and len(s) >= 8}, key=len, reverse=True)

    def scrub(self, text: str) -> str:
        for s in self.secrets:
            text = text.replace(s, "***")
        text = _BOT_URL.sub(lambda m: "/" + (m.group(1) or "") + "bot***", text)
        text = _TOKEN.sub("***", text)
        return _BEARER.sub("Bearer ***", text)

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = self.scrub(record.getMessage())
            record.args = ()
            if record.exc_info and not record.exc_text:
                record.exc_text = self.scrub(logging.Formatter().formatException(record.exc_info))
            elif record.exc_text:
                record.exc_text = self.scrub(record.exc_text)
        except Exception:      # never let logging break the bot
            pass
        return True
