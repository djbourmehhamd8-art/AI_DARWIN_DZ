from __future__ import annotations

import re
import threading
import time
from collections import defaultdict, deque

TG_LIMIT = 4000


def split_text(text: str, limit: int = TG_LIMIT) -> list:
    """Split text into chunks <= limit, preferring newline/space boundaries."""
    if len(text) <= limit:
        return [text]
    parts = []
    while len(text) > limit:
        cut = text.rfind("\n", 0, limit)
        if cut < limit // 2:
            cut = text.rfind(" ", 0, limit)
        if cut < limit // 2:
            cut = limit
        parts.append(text[:cut])
        text = text[cut:].lstrip("\n")
    if text:
        parts.append(text)
    return parts


def est_tokens(text: str) -> int:
    return max(1, len(text) // 3)


class RateLimiter:
    """Sliding-window limiter: `limit` events per `window` seconds per key."""

    def __init__(self, limit: int, window: float = 60.0):
        self.limit = limit
        self.window = window
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key) -> bool:
        if self.limit <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > 5000:
                self._hits = defaultdict(deque, {k: v for k, v in self._hits.items()
                                                  if v and now - v[-1] <= self.window})
            q = self._hits[key]
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True


_DUR_PART = re.compile(r"(\d+)\s*([smhd])", re.I)
_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(s: str):
    """'30s' / '10m' / '2h' / '1d' / '1h30m' / '1d 2h' -> seconds, or None."""
    s = s.strip()
    if not s:
        return None
    pos, total = 0, 0
    for m in _DUR_PART.finditer(s):
        if s[pos:m.start()].strip():
            return None
        total += int(m.group(1)) * _UNIT[m.group(2).lower()]
        pos = m.end()
    if pos == 0 or s[pos:].strip():
        return None
    return total or None


def fmt_duration(sec: int) -> str:
    """1h 30m / 2d 4h / 5m / 40s — at most two units, seconds only below one minute."""
    sec = max(0, int(sec))
    if sec < 60:
        return f"{sec}s"
    d, rem = divmod(sec, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    if d:
        return f"{d}d {h}h" if h else f"{d}d"
    if h:
        return f"{h}h {m}m" if m else f"{h}h"
    return f"{m}m"
