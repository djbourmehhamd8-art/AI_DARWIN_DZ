"""In-memory ring buffer of recent warnings/errors for the web panel's log page (secrets are scrubbed by RedactFilter)."""
from __future__ import annotations

import collections
import logging
import threading
import time


class RingHandler(logging.Handler):
    def __init__(self, capacity: int = 400, level: int = logging.WARNING):
        super().__init__(level)
        self._buf = collections.deque(maxlen=capacity)
        self._mu = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = record.getMessage()
            if record.exc_text:                                     # already scrubbed by the filter; keep only the last line
                msg += " | " + record.exc_text.strip().splitlines()[-1]
            item = (record.created, record.levelname, record.name, msg[:600])
            with self._mu:
                self._buf.append(item)
        except Exception:                                          # logging must never break the bot
            pass

    def records(self, min_level: str = "WARNING", q: str = "", limit: int = 200) -> list:
        floor = getattr(logging, min_level, logging.WARNING)
        q = (q or "").lower()
        with self._mu:
            items = list(self._buf)
        out = [r for r in reversed(items) if getattr(logging, r[1], 0) >= floor and (not q or q in (r[3] + r[2]).lower())]
        return out[:limit]

    def clear(self) -> None:
        with self._mu:
            self._buf.clear()


RING = RingHandler()


def fmt_time(ts: float) -> str:
    return time.strftime("%m-%d %H:%M:%S", time.localtime(ts))
