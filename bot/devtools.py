"""More offline helpers (no network, stdlib only): chmod, CIDR membership, IP conversions, user-agent parsing,
text diff, date arithmetic and Subresource-Integrity hashes. Every function takes plain text, returns plain data
or raises ValueError with a short message (same contract as proutils.py)."""
from __future__ import annotations

import base64
import datetime as dt
import difflib
import hashlib
import ipaddress
import re

MAX_INPUT = 20000


# ---------------------------------------------------------------- chmod
_RWX = "rwx"


def _sym(mode: int) -> str:
    out = ""
    for shift in (6, 3, 0):
        bits = (mode >> shift) & 7
        out += "".join(c if bits & (4 >> i) else "-" for i, c in enumerate(_RWX))
    if mode & 0o4000:
        out = out[:2] + ("s" if out[2] == "x" else "S") + out[3:]
    if mode & 0o2000:
        out = out[:5] + ("s" if out[5] == "x" else "S") + out[6:]
    if mode & 0o1000:
        out = out[:8] + ("t" if out[8] == "x" else "T")
    return out


def chmod_calc(arg: str) -> dict:
    """`755`, `4755`, `rwxr-xr-x`, or `u=rwx,go=rx` (applied to 000)."""
    a = (arg or "").strip()
    if not a:
        raise ValueError("empty input")
    if re.fullmatch(r"[0-7]{3,4}", a):
        mode = int(a, 8)
    elif re.fullmatch(r"[r-][w-][xsStT-][r-][w-][xsStT-][r-][w-][xsStT-]", a):
        mode = 0
        for i, ch in enumerate(a):
            if ch in "rwxsStT":
                if ch in "rwx":
                    mode |= 1 << (8 - i)
                elif ch in "sS" and i in (2, 5):
                    mode |= 0o4000 if i == 2 else 0o2000
                    if ch == "s":
                        mode |= 1 << (8 - i)
                elif ch in "tT" and i == 8:
                    mode |= 0o1000
                    if ch == "t":
                        mode |= 1
                else:
                    raise ValueError("misplaced special bit")
    elif re.fullmatch(r"(?:[ugoa]*[=+-][rwxst]*)(?:,[ugoa]*[=+-][rwxst]*)*", a):
        mode = 0
        for clause in a.split(","):
            who, op, perms = re.fullmatch(r"([ugoa]*)([=+-])([rwxst]*)", clause).groups()
            who = who or "a"
            if "a" in who:
                who = "ugo"
            bits = 0
            for ch in perms:
                for w in who:
                    shift = {"u": 6, "g": 3, "o": 0}[w]
                    if ch in "rwx":
                        bits |= {"r": 4, "w": 2, "x": 1}[ch] << shift
                    elif ch == "s" and w in "ug":
                        bits |= 0o4000 if w == "u" else 0o2000
                    elif ch == "t" and w == "o":
                        bits |= 0o1000
            mask = 0
            for w in who:
                mask |= 7 << {"u": 6, "g": 3, "o": 0}[w]
            if op == "=":
                mode = (mode & ~mask) | bits
            elif op == "+":
                mode |= bits
            else:
                mode &= ~bits
    else:
        raise ValueError("use 755, 4755, rwxr-xr-x or u=rwx,go=rx")
    notes = []
    if mode & 0o002:
        notes.append(("high", "قابل للكتابة من الجميع (world-writable)", "world-writable"))
    if mode & 0o4000:
        notes.append(("high", "setuid: يعمل بصلاحيات المالك", "setuid: runs with the owner's privileges"))
    if mode & 0o2000:
        notes.append(("medium", "setgid", "setgid"))
    if mode & 0o1000 and not mode & 0o002:
        notes.append(("low", "sticky على ملف/مجلد غير عام", "sticky bit without world-write"))
    if mode & 0o004 and mode & 0o200:
        notes.append(("low", "مقروء للجميع", "world-readable"))
    return {"octal": f"{mode:04o}", "symbolic": _sym(mode), "notes": notes,
            "umask": f"{(~mode) & 0o777:03o}", "files_umask_from_666": f"{0o666 & ~mode & 0o777:03o}"}


# ---------------------------------------------------------------- CIDR membership
def cidr_match(arg: str) -> dict:
    """`10.1.2.3 in 10.0.0.0/8, 192.168.0.0/16` — several IPs and several networks are allowed (`::` separates them too)."""
    text = (arg or "")[:MAX_INPUT]
    if not text.strip():
        raise ValueError("empty input")
    sides = re.split(r"\s(?:in|::|->)\s", text, maxsplit=1)
    if len(sides) != 2:
        raise ValueError("format: IP[, IP…] in CIDR[, CIDR…]")
    left, right = sides
    ips, nets = [], []
    for tok in re.split(r"[\s,;]+", left.strip()):
        if tok:
            try:
                ips.append(ipaddress.ip_address(tok))
            except ValueError:
                raise ValueError(f"invalid IP: {tok[:40]}")
    for tok in re.split(r"[\s,;]+", right.strip()):
        if tok:
            try:
                nets.append(ipaddress.ip_network(tok, strict=False))
            except ValueError:
                raise ValueError(f"invalid network: {tok[:40]}")
    if not ips or not nets:
        raise ValueError("need at least one IP and one network")
    if len(ips) > 200 or len(nets) > 200:
        raise ValueError("too many items (max 200 each)")
    rows = []
    for ip in ips:
        hit = [str(n) for n in nets if ip.version == n.version and ip in n]
        rows.append({"ip": str(ip), "match": hit})
    return {"rows": rows, "matched": sum(1 for r in rows if r["match"]), "total": len(rows)}


# ---------------------------------------------------------------- IP conversions
def ip_convert(arg: str) -> list:
    """Return [(label, value)] for an IPv4/IPv6 address, or an integer that becomes an address."""
    a = (arg or "").strip()
    if not a:
        raise ValueError("empty input")
    ip = None
    if re.fullmatch(r"0x[0-9a-fA-F]{1,32}", a):
        n = int(a, 16)
    elif re.fullmatch(r"\d{1,39}", a):
        n = int(a)
    else:
        n = None
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            raise ValueError("send an IPv4/IPv6 address, a decimal number or 0x hex")
    if ip is None:
        if n < 2 ** 32:
            ip = ipaddress.IPv4Address(n)
        elif n < 2 ** 128:
            ip = ipaddress.IPv6Address(n)
        else:
            raise ValueError("number too large")
    rows = [("Address", str(ip)), ("Version", f"IPv{ip.version}"), ("Decimal", str(int(ip))), ("Hex", f"0x{int(ip):0{8 if ip.version == 4 else 32}x}")]
    if ip.version == 4:
        rows.append(("Binary", ".".join(f"{o:08b}" for o in ip.packed)))
        rows.append(("IPv4-mapped IPv6", str(ipaddress.IPv6Address("::ffff:" + str(ip)))))
    else:
        rows.append(("Expanded", ip.exploded))
        if ip.ipv4_mapped:
            rows.append(("Mapped IPv4", str(ip.ipv4_mapped)))
    rows.append(("Reverse pointer", ip.reverse_pointer))
    kinds = [n for n in ("private", "loopback", "link_local", "multicast", "reserved", "global") if getattr(ip, "is_" + n)]
    rows.append(("Scope", ", ".join(kinds) or "-"))
    return rows


# ---------------------------------------------------------------- user agent
_BROWSERS = (("Edge", r"Edg(?:e|A|iOS)?/([\d.]+)"), ("Opera", r"OPR/([\d.]+)"), ("Samsung Internet", r"SamsungBrowser/([\d.]+)"),
             ("Firefox", r"(?:Firefox|FxiOS)/([\d.]+)"), ("Chrome", r"(?:Chrome|CriOS)/([\d.]+)"), ("Safari", r"Version/([\d.]+).*Safari"),
             ("curl", r"curl/([\d.]+)"), ("Wget", r"Wget/([\d.]+)"), ("python-requests", r"python-requests/([\d.]+)"),
             ("Go-http-client", r"Go-http-client/([\d.]+)"), ("okhttp", r"okhttp/([\d.]+)"))
_OSES = (("Windows", r"Windows NT ([\d.]+)"), ("Android", r"Android ([\d.]+)"), ("iOS", r"(?:iPhone|iPad).*OS ([\d_]+)"),
         ("macOS", r"Mac OS X ([\d_]+)"), ("ChromeOS", r"CrOS"), ("Linux", r"Linux"))
_BOTS = re.compile(r"bot|crawl|spider|slurp|facebookexternalhit|preview|monitor|scanner|nikto|sqlmap|nmap|masscan|zgrab|headless|phantomjs|selenium|puppeteer|playwright", re.I)
_WIN = {"10.0": "10/11", "6.3": "8.1", "6.2": "8", "6.1": "7", "6.0": "Vista", "5.1": "XP"}


def parse_user_agent(arg: str) -> dict:
    ua = (arg or "").strip().strip('"')[:2000]
    ua = re.sub(r"^user-agent\s*:\s*", "", ua, flags=re.I)
    if not ua:
        raise ValueError("empty input")
    browser = next(((n, m.group(1)) for n, rx in _BROWSERS if (m := re.search(rx, ua))), ("unknown", ""))
    os_ = ("unknown", "")
    for n, rx in _OSES:
        m = re.search(rx, ua)
        if m:
            v = (m.group(1) if m.groups() else "").replace("_", ".")
            os_ = (n, _WIN.get(v, v) if n == "Windows" else v)
            break
    flags = []
    if _BOTS.search(ua):
        flags.append(("medium", "يبدو آلة/زاحفاً/أداة فحص", "looks like a bot / crawler / scanner"))
    if "HeadlessChrome" in ua:
        flags.append(("medium", "متصفح بلا واجهة (Headless)", "headless browser"))
    if re.search(r"sqlmap|nikto|nmap|masscan|zgrab|wpscan|acunetix|nessus|burp", ua, re.I):
        flags.append(("high", "توقيع أداة اختبار اختراق معروفة", "signature of a known pentest/scanning tool"))
    if re.search(r"MSIE [1-8]\.|Chrome/[1-9]\.|Firefox/[1-9]\.", ua):
        flags.append(("low", "إصدار متصفح قديم جداً (قد يكون مزيفاً)", "very old browser version (possibly spoofed)"))
    if len(ua) < 12:
        flags.append(("low", "وكيل مستخدم قصير جداً", "very short user agent"))
    if len(ua) > 600:
        flags.append(("medium", "وكيل مستخدم طويل بشكل مريب", "suspiciously long user agent"))
    if re.search(r"[<>'\"`]|\$\{|\bUNION\b|\.\./", ua):
        flags.append(("high", "محارف حقن داخل User-Agent", "injection characters inside the User-Agent"))
    mobile = bool(re.search(r"Mobile|Android|iPhone|iPad", ua))
    return {"browser": browser[0], "browser_version": browser[1], "os": os_[0], "os_version": os_[1], "mobile": mobile, "flags": flags, "length": len(ua)}


# ---------------------------------------------------------------- diff
def text_diff(arg: str) -> dict:
    """Two texts separated by a line containing only `---` or by `::`. Returns a unified diff."""
    text = (arg or "")[:MAX_INPUT * 2]
    if re.search(r"(?m)^\s*(?:---|:::?)\s*$", text):
        a, b = re.split(r"(?m)^\s*(?:---|:::?)\s*$", text, maxsplit=1)
    elif " :: " in text:
        a, b = text.split(" :: ", 1)
    else:
        raise ValueError("separate the two texts with a line containing only --- (or ' :: ')")
    la, lb = a.strip("\n").splitlines(), b.strip("\n").splitlines()
    if len(la) > 2000 or len(lb) > 2000:
        raise ValueError("too many lines (max 2000 each)")
    d = list(difflib.unified_diff(la, lb, "A", "B", lineterm="", n=2))
    added = sum(1 for x in d if x.startswith("+") and not x.startswith("+++"))
    removed = sum(1 for x in d if x.startswith("-") and not x.startswith("---"))
    ratio = round(difflib.SequenceMatcher(None, "\n".join(la), "\n".join(lb), autojunk=True).quick_ratio() * 100, 1)
    return {"diff": "\n".join(d), "added": added, "removed": removed, "similarity": ratio, "identical": la == lb}


# ---------------------------------------------------------------- date arithmetic
_UNITS = {"d": 1, "w": 7}


def date_calc(arg: str, today: "dt.date | None" = None) -> dict:
    """`2026-01-01 to 2026-03-01` (difference) · `2026-01-01 + 90d` / `- 2w` (shift) · `today + 30d` · `2026-11-24` (info)."""
    a = " ".join((arg or "").split())[:200]
    if not a:
        raise ValueError("empty input")
    today = today or dt.datetime.now(dt.timezone.utc).date()

    def d(tok: str) -> dt.date:
        if tok.lower() in ("today", "now"):
            return today
        try:
            return dt.date.fromisoformat(tok)
        except ValueError:
            raise ValueError(f"invalid date (use YYYY-MM-DD): {tok[:20]}")
    m = re.fullmatch(r"(\S+)\s+(?:to|->|until)\s+(\S+)", a, re.I)
    if m:
        x, y = d(m.group(1)), d(m.group(2))
        days = (y - x).days
        return {"kind": "diff", "from": x.isoformat(), "to": y.isoformat(), "days": days, "weeks": round(days / 7, 1),
                "approx_months": round(days / 30.4375, 1)}
    m = re.fullmatch(r"(today|now|\d{4}-\d{2}-\d{2})\s*([+-])\s*(\d{1,6})\s*([dw]?)", a, re.I)
    if m:
        base, sign, n, unit = d(m.group(1)), m.group(2), int(m.group(3)), (m.group(4) or "d").lower()
        delta = dt.timedelta(days=n * _UNITS[unit])
        try:
            res = base + delta if sign == "+" else base - delta
        except OverflowError:
            raise ValueError("result out of range")
        return {"kind": "shift", "base": base.isoformat(), "result": res.isoformat(), "weekday": res.strftime("%A"),
                "days_from_today": (res - today).days}
    x = d(a)
    return {"kind": "info", "date": x.isoformat(), "weekday": x.strftime("%A"), "day_of_year": x.timetuple().tm_yday,
            "iso_week": x.isocalendar()[1], "days_from_today": (x - today).days, "unix": int(dt.datetime(x.year, x.month, x.day, tzinfo=dt.timezone.utc).timestamp())}


# ---------------------------------------------------------------- Subresource Integrity
def sri_hash(text: str) -> dict:
    data = (text or "")
    if not data.strip():
        raise ValueError("empty input")
    raw = data.encode("utf-8")
    if len(raw) > 5_000_000:
        raise ValueError("too large")
    out = {}
    for name in ("sha256", "sha384", "sha512"):
        out[name] = f"{name}-" + base64.b64encode(hashlib.new(name, raw).digest()).decode()
    return {"hashes": out, "bytes": len(raw), "tag": f'<script src="…" integrity="{out["sha384"]}" crossorigin="anonymous"></script>'}
