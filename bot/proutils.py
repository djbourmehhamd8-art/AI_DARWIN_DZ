"""Pure, offline helper functions behind the "extra tools" (no network, no Telegram): used by the bot buttons AND the web panel.

Every function takes plain text and returns plain data (or raises ValueError with a short message), so it is easy to test.
"""
from __future__ import annotations

import ast
import base64
import binascii
import colorsys
import datetime as _dt
import ipaddress
import itertools
import json
import math
import operator
import re
import secrets
import string
import threading
import urllib.parse
import uuid
from collections import Counter

MAX_INPUT = 20000

# ---------------------------------------------------------------- calculator (AST whitelist, never eval)
_BIN = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv,
        ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod, ast.Pow: operator.pow}
_UN = {ast.UAdd: operator.pos, ast.USub: operator.neg}
_FUNCS = {"sqrt": math.sqrt, "sin": math.sin, "cos": math.cos, "tan": math.tan, "log": math.log, "log2": math.log2,
          "log10": math.log10, "abs": abs, "round": round, "floor": math.floor, "ceil": math.ceil, "exp": math.exp,
          "factorial": math.factorial, "min": min, "max": max}
_CONST = {"pi": math.pi, "e": math.e, "tau": math.tau}


def calc(expr: str):
    expr = (expr or "").strip().replace("^", "**").replace("×", "*").replace("÷", "/")
    if not expr or len(expr) > 200:
        raise ValueError("empty or too long")
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError:
        raise ValueError("bad expression")

    def ev(n, depth=0):
        if depth > 40:
            raise ValueError("too deep")
        if isinstance(n, ast.Expression):
            return ev(n.body, depth + 1)
        if isinstance(n, ast.Constant) and isinstance(n.value, (int, float)) and not isinstance(n.value, bool):
            return n.value
        if isinstance(n, ast.Name) and n.id in _CONST:
            return _CONST[n.id]
        if isinstance(n, ast.BinOp) and type(n.op) in _BIN:
            a, b = ev(n.left, depth + 1), ev(n.right, depth + 1)
            if isinstance(n.op, ast.Pow) and (abs(b) > 1000 or abs(a) > 10 ** 6):
                raise ValueError("power too large")
            return _BIN[type(n.op)](a, b)
        if isinstance(n, ast.UnaryOp) and type(n.op) in _UN:
            return _UN[type(n.op)](ev(n.operand, depth + 1))
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in _FUNCS and not n.keywords and len(n.args) <= 4:
            args = [ev(a, depth + 1) for a in n.args]
            if n.func.id == "factorial" and (not isinstance(args[0], int) or args[0] > 500):
                raise ValueError("factorial too large")
            return _FUNCS[n.func.id](*args)
        raise ValueError("unsupported")
    try:
        r = ev(tree)
    except ZeroDivisionError:
        raise ValueError("division by zero")
    except (OverflowError, TypeError):
        raise ValueError("cannot compute")
    if isinstance(r, complex):                                      # (-8)**0.5 -> complex in Python: not a real number
        raise ValueError("cannot compute")
    if isinstance(r, float):
        if math.isnan(r) or math.isinf(r):
            raise ValueError("cannot compute")
        r = round(r, 12)
        if r == int(r) and abs(r) < 1e15:
            r = int(r)
    return r


# ---------------------------------------------------------------- JSON
def json_pretty(text: str) -> dict:
    text = (text or "").strip()
    if not text:
        raise ValueError("empty")
    depth = peak = 0
    in_str = esc = False
    for ch in text:                                         # explicit bound: newer CPython parses 5000 levels fine, older ones crash/recurse
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            peak = max(peak, depth)
            if peak > 200:
                raise ValueError("JSON is nested too deeply")
        elif ch in "]}":
            depth -= 1
    try:
        obj = json.loads(text)
        kind = type(obj).__name__
        size = len(obj) if isinstance(obj, (dict, list)) else 1
        return {"pretty": json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=False),
                "compact": json.dumps(obj, ensure_ascii=False, separators=(",", ":")), "type": kind, "size": size}
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid JSON: line {e.lineno} col {e.colno}: {e.msg}")
    except RecursionError:                                  # "[[[[[…" nested a thousand levels deep
        raise ValueError("JSON is nested too deeply")


# ---------------------------------------------------------------- regex tester ("pattern :: text")
def regex_test(arg: str) -> dict:
    if "::" not in (arg or ""):
        raise ValueError("format: pattern :: text")
    pat, text = arg.split("::", 1)
    pat, text = pat.strip(), text.strip("\n").lstrip(" ")
    if not pat:
        raise ValueError("empty pattern")
    if len(pat) > 300 or len(text) > 5000:
        raise ValueError("input too long")
    if (re.search(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]", pat)
            or re.search(r"\((?:[^()\\]|\\.)*\|(?:[^()\\]|\\.)*\)[+*{]", pat)):   # (a+)+ style: catastrophic backtracking
        raise ValueError("pattern rejected (nested quantifiers can hang the bot)")
    try:
        re.compile(pat)
    except re.error as e:
        raise ValueError(f"invalid pattern: {e}")
    return _regex_isolated(pat, text)


_REGEX_CHILD = (
    "import json,re,sys\n"
    "try:\n"
    " import resource\n"
    " resource.setrlimit(resource.RLIMIT_AS,(768<<20,768<<20))\n"      # a hostile pattern cannot eat the host's RAM
    " resource.setrlimit(resource.RLIMIT_CPU,(5,5))\n"                 # hard CPU backstop next to the caller's wall-clock timeout
    "except Exception:\n"
    " pass\n"
    "d=json.loads(sys.stdin.read())\n"
    "rx=re.compile(d['p'])\n"
    "out=[]\n"
    "for m in rx.finditer(d['t']):\n"
    " out.append({'span':list(m.span()),'text':m.group(0)[:200],'groups':[g[:100] if g else g for g in m.groups()]})\n"
    " if len(out)>=20: break\n"
    "print(json.dumps(out))\n"
)


_REGEX_SLOTS = threading.BoundedSemaphore(4)


def _regex_isolated(pat: str, text: str, timeout: float = 2.0) -> dict:
    """Match in a throw-away interpreter. The `re` engine never releases the GIL, so a pattern like (a?){30}a{30} in-process would freeze the
    whole bot (and the web panel); a child process can simply be killed. The nested-quantifier check above is only a cheap first filter."""
    import subprocess
    import sys
    if not _REGEX_SLOTS.acquire(blocking=False):                     # the public /t page is unauthenticated: never fork without a ceiling
        raise ValueError("regex tester busy, try again in a moment")
    try:
        r = subprocess.run([sys.executable, "-I", "-c", _REGEX_CHILD], input=json.dumps({"p": pat, "t": text}),
                           capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise ValueError("pattern too slow (possible catastrophic backtracking) - stopped")
    except OSError:
        raise ValueError("regex sandbox unavailable")
    finally:
        _REGEX_SLOTS.release()
    if r.returncode != 0:
        raise ValueError("pattern could not be evaluated")
    out = json.loads(r.stdout or "[]")
    for m in out:
        m["span"] = tuple(m["span"])
    return {"pattern": pat, "count": len(out), "matches": out}


# ---------------------------------------------------------------- text statistics
def text_stats(text: str) -> dict:
    text = (text or "")[:MAX_INPUT]
    if not text.strip():
        raise ValueError("empty")
    words = re.findall(r"\w+", text, re.UNICODE)
    top = Counter(w.lower() for w in words if len(w) > 2).most_common(5)
    return {"chars": len(text), "chars_no_space": len(re.sub(r"\s", "", text)), "words": len(words),
            "lines": text.count("\n") + 1, "unique_words": len({w.lower() for w in words}),
            "bytes": len(text.encode("utf-8")), "top": top,
            "read_minutes": max(1, round(len(words) / 200))}


# ---------------------------------------------------------------- unit conversion  ("10 km to mi")
_LEN = {"mm": 0.001, "cm": 0.01, "m": 1, "km": 1000, "in": 0.0254, "ft": 0.3048, "yd": 0.9144, "mi": 1609.344, "nmi": 1852}
_MASS = {"mg": 1e-6, "g": 0.001, "kg": 1, "t": 1000, "oz": 0.028349523125, "lb": 0.45359237}
_DATA = {"bit": 0.125, "byte": 1, "kb": 1000, "mb": 1e6, "gb": 1e9, "tb": 1e12, "kib": 1024, "mib": 1024 ** 2, "gib": 1024 ** 3,
         "tib": 1024 ** 4}                                   # base unit: byte
_TIME = {"ms": 0.001, "s": 1, "min": 60, "h": 3600, "d": 86400, "w": 604800}
_SPEED = {"m/s": 1, "km/h": 1 / 3.6, "mph": 0.44704, "kn": 0.514444}
_GROUPS = (("length", _LEN), ("mass", _MASS), ("data", _DATA), ("time", _TIME), ("speed", _SPEED))


def convert_units(arg: str) -> dict:
    m = re.match(r"^\s*(-?\d+(?:[.,]\d+)?)\s*([a-zA-Z/°]+)\s*(?:to|in|->|→|الى|إلى)\s*([a-zA-Z/°]+)\s*$", arg or "")
    if not m:
        raise ValueError("format: 10 km to mi")
    val = float(m.group(1).replace(",", "."))
    a, b = m.group(2).lower(), m.group(3).lower()
    temps = {"c", "f", "k", "°c", "°f"}
    if a in temps and b in temps:
        a, b = a.strip("°"), b.strip("°")
        c = val if a == "c" else (val - 32) * 5 / 9 if a == "f" else val - 273.15
        r = c if b == "c" else c * 9 / 5 + 32 if b == "f" else c + 273.15
        return {"value": val, "from": a.upper(), "to": b.upper(), "result": round(r, 6), "group": "temperature"}
    for name, table in _GROUPS:
        if a in table and b in table:
            return {"value": val, "from": a, "to": b, "result": round(val * table[a] / table[b], 8), "group": name}
    raise ValueError("unknown or mixed units")


# ---------------------------------------------------------------- colours
def color_convert(arg: str) -> dict:
    s = (arg or "").strip().lower()
    m = re.fullmatch(r"#?([0-9a-f]{6}|[0-9a-f]{3})", s)
    if m:
        h = m.group(1)
        if len(h) == 3:
            h = "".join(c * 2 for c in h)
        r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    else:
        m = re.fullmatch(r"(?:rgb\()?\s*(\d{1,3})[\s,]+(\d{1,3})[\s,]+(\d{1,3})\s*\)?", s)
        if not m:
            raise ValueError("format: #1f6feb or 31 111 235")
        r, g, b = (int(x) for x in m.groups())
        if max(r, g, b) > 255:
            raise ValueError("RGB values are 0-255")
    hh, ll, ss = colorsys.rgb_to_hls(r / 255, g / 255, b / 255)
    return {"hex": f"#{r:02x}{g:02x}{b:02x}", "rgb": f"rgb({r}, {g}, {b})",
            "hsl": f"hsl({round(hh * 360)}, {round(ss * 100)}%, {round(ll * 100)}%)"}


# ---------------------------------------------------------------- encodings
def b64(text: str, decode: bool | None = None) -> dict:
    text = (text or "").strip()
    if not text:
        raise ValueError("empty")
    if decode is None:                      # auto: decode only if it round-trips as printable UTF-8
        try:
            raw = base64.b64decode(text, validate=True)
            raw.decode("utf-8")
            decode = len(text) % 4 == 0 and len(text) >= 4
        except (binascii.Error, UnicodeDecodeError, ValueError):
            decode = False
    if decode:
        try:
            return {"mode": "decode", "result": base64.b64decode(text + "=" * (-len(text) % 4)).decode("utf-8", "replace")}
        except (binascii.Error, ValueError):
            raise ValueError("not valid Base64")
    return {"mode": "encode", "result": base64.b64encode(text.encode("utf-8")).decode()}


def url_codec(text: str) -> dict:
    text = (text or "").strip()
    if not text:
        raise ValueError("empty")
    if re.search(r"%[0-9a-fA-F]{2}", text):
        return {"mode": "decode", "result": urllib.parse.unquote(text)}
    return {"mode": "encode", "result": urllib.parse.quote(text, safe="")}


# ---------------------------------------------------------------- generators
def make_uuids(n: int = 3) -> list:
    return [str(uuid.uuid4()) for _ in range(max(1, min(n, 10)))]


def rand_roll(arg: str) -> dict:
    """'' -> 1..100; '6' -> 1..6; '2d6' -> two dice; '10 20' -> range; 'coin'."""
    s = (arg or "").strip().lower()
    if s in ("coin", "عملة"):
        return {"kind": "coin", "result": secrets.choice(["Heads / صورة", "Tails / كتابة"])}
    m = re.fullmatch(r"(\d{1,2})d(\d{1,4})", s)
    if m:
        k, sides = int(m.group(1)), int(m.group(2))
        if not (1 <= k <= 20 and 2 <= sides <= 1000):
            raise ValueError("1-20 dice, 2-1000 sides")
        rolls = [secrets.randbelow(sides) + 1 for _ in range(k)]
        return {"kind": "dice", "rolls": rolls, "result": sum(rolls)}
    nums = re.findall(r"-?\d+", s)
    lo, hi = (1, 100) if not nums else (1, int(nums[0])) if len(nums) == 1 else (int(nums[0]), int(nums[1]))
    if lo > hi:
        lo, hi = hi, lo
    if hi - lo > 10 ** 12:
        raise ValueError("range too large")
    return {"kind": "range", "lo": lo, "hi": hi, "result": lo + secrets.randbelow(hi - lo + 1)}


def make_password(length: int = 20, symbols: bool = True) -> str:
    length = max(8, min(int(length), 128))
    alpha = string.ascii_letters + string.digits + ("!@#$%^&*-_=+?" if symbols else "")
    while True:
        pw = "".join(secrets.choice(alpha) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw)
                and (not symbols or any(c in "!@#$%^&*-_=+?" for c in pw))):
            return pw


def slugify(text: str) -> str:
    s = re.sub(r"[^\w\s-]", "", (text or "").strip().lower(), flags=re.UNICODE)
    s = re.sub(r"[\s_]+", "-", s).strip("-")
    if not s:
        raise ValueError("empty")
    return s[:120]


def case_convert(text: str) -> list:
    words = re.findall(r"[A-Za-z؀-ۿ0-9]+", re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text or ""))
    if not words:
        raise ValueError("empty")
    lw = [w.lower() for w in words]
    return [("snake_case", "_".join(lw)), ("kebab-case", "-".join(lw)), ("camelCase", lw[0] + "".join(w.title() for w in lw[1:])),
            ("PascalCase", "".join(w.title() for w in lw)), ("CONSTANT_CASE", "_".join(lw).upper()),
            ("Title Case", " ".join(w.title() for w in lw))]


# ---------------------------------------------------------------- list helpers
def dedupe_sort(text: str) -> dict:
    lines = [ln.strip() for ln in (text or "")[:MAX_INPUT].splitlines() if ln.strip()]
    if not lines:
        raise ValueError("empty")
    uniq = sorted(set(lines), key=str.lower)
    return {"total": len(lines), "unique": len(uniq), "removed": len(lines) - len(uniq), "result": "\n".join(uniq[:300])}


def percent(arg: str) -> dict:
    """'15% of 200' / '30 of 120' / '50 to 75' (change)."""
    s = (arg or "").lower().replace(",", ".")
    m = re.fullmatch(r"\s*(-?\d+(?:\.\d+)?)\s*%\s*(?:of|من)\s*(-?\d+(?:\.\d+)?)\s*", s)
    if m:
        return {"text": f"{m.group(1)}% of {m.group(2)} = {round(float(m.group(1)) * float(m.group(2)) / 100, 6):g}"}
    m = re.fullmatch(r"\s*(-?\d+(?:\.\d+)?)\s*(?:of|من)\s*(-?\d+(?:\.\d+)?)\s*", s)
    if m:
        b = float(m.group(2))
        if b == 0:
            raise ValueError("division by zero")
        return {"text": f"{m.group(1)} / {m.group(2)} = {round(float(m.group(1)) / b * 100, 4):g}%"}
    m = re.fullmatch(r"\s*(-?\d+(?:\.\d+)?)\s*(?:to|->|→|الى|إلى)\s*(-?\d+(?:\.\d+)?)\s*", s)
    if m:
        a = float(m.group(1))
        if a == 0:
            raise ValueError("division by zero")
        return {"text": f"{m.group(1)} → {m.group(2)}: {round((float(m.group(2)) - a) / abs(a) * 100, 4):+g}%"}
    raise ValueError("format: 15% of 200 | 30 of 120 | 50 to 75")


# ---------------------------------------------------------------- subnet calculator
def subnet_calc(arg: str) -> dict:
    """`10.0.0.0/24`, `192.168.1.10 255.255.255.0`, or either followed by `/26` / `to 26` to split into smaller subnets."""
    parts = (arg or "").replace(",", " ").split()
    if not parts:
        raise ValueError("empty input")
    split_to = None
    if len(parts) >= 2 and parts[-1].lstrip("/").isdigit() and (parts[-2].lower() == "to" or "/" in parts[0] or len(parts) == 3):
        split_to = int(parts[-1].lstrip("/"))
        parts = [p for p in parts[:-1] if p.lower() != "to"]
    try:
        net = ipaddress.ip_network("/".join(parts) if len(parts) == 2 and "/" not in parts[0] and "." not in parts[1] else
                                   (parts[0] + "/" + parts[1] if len(parts) == 2 else parts[0]), strict=False)
    except ValueError as e:
        raise ValueError(f"invalid network: {str(e)[:80]}")
    v4 = net.version == 4
    n = net.num_addresses
    hosts = max(n - 2, 0) if v4 and net.prefixlen < 31 else n
    first = net[1] if v4 and net.prefixlen < 31 else net[0]
    last = net[-2] if v4 and net.prefixlen < 31 else net[-1]
    out = {"version": net.version, "network": str(net.network_address), "prefix": net.prefixlen, "netmask": str(net.netmask),
           "wildcard": str(net.hostmask) if v4 else "", "broadcast": str(net.broadcast_address) if v4 else "",
           "first": str(first), "last": str(last), "hosts": hosts, "addresses": n, "private": net.is_private,
           "cidr": str(net), "subnets": [], "subnet_count": 0}
    if split_to is not None:
        if split_to <= net.prefixlen or split_to > net.max_prefixlen:
            raise ValueError(f"split prefix must be between /{net.prefixlen + 1} and /{net.max_prefixlen}")
        if split_to - net.prefixlen > 16:
            raise ValueError("too many subnets (max 2^16)")
        out["subnet_count"] = 2 ** (split_to - net.prefixlen)
        out["subnets"] = [str(x) for x in itertools.islice(net.subnets(new_prefix=split_to), 16)]
    return out


# ---------------------------------------------------------------- cron explainer
_MONTHS = {m: i for i, m in enumerate("jan feb mar apr may jun jul aug sep oct nov dec".split(), 1)}
_DOWS = {d: i for i, d in enumerate("sun mon tue wed thu fri sat".split())}
_MACROS = {"@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *", "@monthly": "0 0 1 * *", "@weekly": "0 0 * * 0",
           "@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@hourly": "0 * * * *"}
_FIELDS = ((0, 59, None), (0, 23, None), (1, 31, None), (1, 12, _MONTHS), (0, 7, _DOWS))
_FIELD_NAMES = (("الدقيقة", "minute"), ("الساعة", "hour"), ("يوم الشهر", "day of month"), ("الشهر", "month"), ("يوم الأسبوع", "day of week"))


def _cron_field(text: str, lo: int, hi: int, names) -> set:
    vals: set = set()
    for item in text.split(","):
        if not item:
            raise ValueError("empty list item")
        base, _, step = item.partition("/")
        if step and (not step.isdigit() or int(step) < 1):
            raise ValueError(f"bad step: {step[:10]}")
        st = int(step) if step else 1

        def num(x: str) -> int:
            x = x.lower()
            if names and x in names:
                return names[x]
            if not x.isdigit():
                raise ValueError(f"bad value: {x[:12]}")
            return int(x)
        if base in ("*", "?"):
            a, b = lo, hi
        elif "-" in base:
            l, _, r = base.partition("-")
            a, b = num(l), num(r)
        else:
            a = num(base)
            b = hi if step else a
        if not (lo <= a <= hi and lo <= b <= hi) or a > b:
            raise ValueError(f"value out of range {lo}-{hi}: {item[:12]}")
        vals.update(range(a, b + 1, st))
    return vals


def _cron_phrase(raw: str, i: int, vals: set) -> tuple:
    ar, en = _FIELD_NAMES[i]
    if raw in ("*", "?"):
        return (f"كل {ar}", f"every {en}")
    if raw.startswith("*/") and raw[2:].isdigit():
        return (f"كل {raw[2:]} من ({ar})", f"every {raw[2:]} ({en})")
    shown = ", ".join(map(str, sorted(vals)[:12])) + ("…" if len(vals) > 12 else "")
    return (f"{ar}: {shown}", f"{en}: {shown}")


def cron_explain(expr: str, count: int = 5, start: "_dt.datetime | None" = None) -> dict:
    """Parse a 5-field cron expression (or @macro), explain each field and list the next runs (UTC)."""
    e = " ".join((expr or "").split())[:200]
    e = re.sub(r"^(?:cron\s*[:=]\s*)", "", e, flags=re.I)
    e = _MACROS.get(e.lower(), e)
    f = e.split(" ")
    if len(f) != 5:
        raise ValueError("expected 5 fields: minute hour day-of-month month day-of-week")
    sets = [_cron_field(x, *_FIELDS[i]) for i, x in enumerate(f)]
    sets[4] = {d % 7 for d in sets[4]}                      # 7 == Sunday
    dom_star, dow_star = f[2] in ("*", "?"), f[4] in ("*", "?")
    start = (start or _dt.datetime.now(_dt.timezone.utc)).replace(second=0, microsecond=0)
    runs: list = []
    day = start.replace(hour=0, minute=0)
    for _ in range(366 * 8):
        if day.month in sets[3]:
            in_dom, in_dow = day.day in sets[2], (day.isoweekday() % 7) in sets[4]
            ok = (in_dom and in_dow) if (dom_star or dow_star) else (in_dom or in_dow)
            if ok:
                for h in sorted(sets[1]):
                    for m in sorted(sets[0]):
                        t = day.replace(hour=h, minute=m)
                        if t > start:
                            runs.append(t.strftime("%Y-%m-%d %H:%M UTC (%a)"))
                            if len(runs) >= count:
                                break
                    if len(runs) >= count:
                        break
        if len(runs) >= count:
            break
        day += _dt.timedelta(days=1)
    fields = [{"raw": f[i], "phrase": _cron_phrase(f[i], i, sets[i])} for i in range(5)]
    return {"expr": e, "fields": fields, "next": runs, "dom_dow_or": not (dom_star or dow_star)}

