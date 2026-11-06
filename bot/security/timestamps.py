"""Convert the timestamp formats seen in DFIR (Unix s/ms/µs, Windows FILETIME, WebKit) to UTC, or ISO -> epoch."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_WIN = datetime(1601, 1, 1, tzinfo=timezone.utc)
_LO, _HI = datetime(1995, 1, 1, tzinfo=timezone.utc), datetime(2100, 1, 1, tzinfo=timezone.utc)


def _try(base, **kw):
    try:
        d = base + timedelta(**kw)
    except OverflowError:
        return None
    return d if _LO <= d <= _HI else None


def analyze(text: str) -> dict:
    s = text.strip().replace("_", "")
    if re.fullmatch(r"-?\d+(\.\d+)?", s):
        v = float(s)
        cands = [("Unix (seconds)", _try(_EPOCH, seconds=v)),
                 ("Unix (milliseconds)", _try(_EPOCH, milliseconds=v)),
                 ("Unix (microseconds)", _try(_EPOCH, microseconds=v)),
                 ("Windows FILETIME (100 ns)", _try(_WIN, microseconds=v / 10)),
                 ("WebKit/Chrome (µs since 1601)", _try(_WIN, microseconds=v))]
        found = [(n, d.strftime("%Y-%m-%d %H:%M:%S UTC")) for n, d in cands if d]
        return {"ok": bool(found), "kind": "decode", "items": found}
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00").replace(" UTC", "+00:00"))
    except ValueError:
        return {"ok": False}
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    d = d.astimezone(timezone.utc)
    secs = (d - _EPOCH).total_seconds()
    ft = int((d - _WIN).total_seconds() * 10_000_000)
    return {"ok": True, "kind": "encode", "items": [
        ("UTC", d.strftime("%Y-%m-%d %H:%M:%S UTC")), ("Unix (seconds)", str(int(secs))),
        ("Unix (milliseconds)", str(int(secs * 1000))), ("Windows FILETIME", str(ft))]}
