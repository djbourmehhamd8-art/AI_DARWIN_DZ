"""Pool of API keys for ONE provider: when a key fails the next one is used, failed keys rest for a while."""
from __future__ import annotations

import threading
import time

# seconds a key rests after a failure with this HTTP status (0 = network error / broken stream)
COOLDOWN = {401: 3600, 402: 3600, 403: 3600, 429: 60, 0: 30}
DEFAULT_COOLDOWN = 30


def mask(key: str) -> str:
    return f"{key[:4]}…{key[-4:]}" if len(key) > 12 else "***"


def parse_keys(*values) -> list:
    """Accept strings (comma / space / newline separated) or iterables; keep order, drop blanks and duplicates."""
    out, seen = [], set()
    for v in values:
        items = v.replace("\n", ",").replace(";", ",").split(",") if isinstance(v, str) else list(v or ())
        for k in items:
            k = k.strip().strip('"').strip("'")
            if k and k not in seen:
                seen.add(k)
                out.append(k)
    return out


class KeyPool:
    def __init__(self, keys, strategy: str = "failover", clock=time.monotonic):
        self.keys = parse_keys(keys)
        if not self.keys:
            raise ValueError("at least one API key is required")
        self.strategy = strategy if strategy in ("failover", "roundrobin") else "failover"
        self._clock = clock
        self._mu = threading.Lock()
        self._until = {k: 0.0 for k in self.keys}
        self._fails = {k: 0 for k in self.keys}
        self._last = {k: None for k in self.keys}
        self._cur = 0
        self._rr = 0
        self.on_event = None            # callback(kind, key, status, available_count) — kinds: "down", "up"

    def __len__(self) -> int:
        return len(self.keys)

    def order(self) -> list:
        """Keys to try for one request: healthy ones first (sticky current key, or rotating), then resting ones."""
        with self._mu:
            now = self._clock()
            n = len(self.keys)
            start = self._cur
            if self.strategy == "roundrobin":
                start = self._rr
                self._rr = (self._rr + 1) % n
            ring = [self.keys[(start + i) % n] for i in range(n)]
            ready = [k for k in ring if self._until[k] <= now]
            resting = sorted((k for k in ring if self._until[k] > now), key=lambda k: self._until[k])
            return ready + resting

    def available(self) -> int:
        with self._mu:
            now = self._clock()
            return sum(1 for k in self.keys if self._until[k] <= now)

    def ok(self, key: str) -> None:
        with self._mu:
            was_down = self._until[key] > 0 or self._fails[key] > 0
            self._until[key], self._fails[key], self._last[key] = 0.0, 0, None
            if self.strategy == "failover":
                self._cur = self.keys.index(key)
            avail = sum(1 for k in self.keys if self._until[k] <= self._clock())
        if was_down and self.on_event:
            self.on_event("up", key, 200, avail)

    def fail(self, key: str, status: int) -> None:
        with self._mu:
            self._until[key] = self._clock() + COOLDOWN.get(status, DEFAULT_COOLDOWN)
            self._fails[key] += 1
            self._last[key] = status
            if self.keys[self._cur] == key:
                self._cur = (self._cur + 1) % len(self.keys)
            now = self._clock()
            avail = sum(1 for k in self.keys if self._until[k] <= now)
        if self.on_event:
            self.on_event("down", key, status, avail)

    def status(self) -> list:
        with self._mu:
            now = self._clock()
            return [{"key": mask(k), "ok": self._until[k] <= now, "retry_in": max(0, int(self._until[k] - now)),
                     "fails": self._fails[k], "last": self._last[k], "current": i == self._cur}
                    for i, k in enumerate(self.keys)]
