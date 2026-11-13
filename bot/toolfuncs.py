"""Small offline helpers behind /hex, /caesar and /entropy. Pure functions, no network, nothing is stored."""
from __future__ import annotations

import math
import re
import string
from collections import Counter

MAX_INPUT = 4000
_HEX_BYTES = re.compile(r"^(?:\s*(?:0x|\\x)?[0-9a-fA-F]{2}\s*[:\-]?)+$")


def hex_convert(arg: str) -> list:
    """Auto-detect: integer -> dec/hex/bin/oct; hex bytes -> text; anything else -> hex of its UTF-8 bytes."""
    s = (arg or "").strip()[:MAX_INPUT]
    if not s:
        return []
    if re.fullmatch(r"-?\d{1,40}", s):
        n = int(s)
        return [("dec", str(n)), ("hex", hex(n)), ("bin", bin(n)), ("oct", oct(n))]
    if re.fullmatch(r"0[xX][0-9a-fA-F]{1,40}", s):
        n = int(s, 16)
        return [("hex", hex(n)), ("dec", str(n)), ("bin", bin(n)), ("oct", oct(n))]
    if _HEX_BYTES.match(s) and len(re.sub(r"0x|\\x|[^0-9a-fA-F]", "", s, flags=re.I)) % 2 == 0 and len(s) >= 4:
        raw = bytes.fromhex(re.sub(r"0x|\\x|[^0-9a-fA-F]", "", s, flags=re.I))
        text = raw.decode("utf-8", "replace")
        printable = all(c in string.printable or ord(c) > 127 for c in text) and "\ufffd" not in text
        out = [("bytes", str(len(raw)))]
        out.append(("text", text if printable else "(not printable text)"))
        out.append(("base64", __import__("base64").b64encode(raw).decode()))
        return out
    raw = s.encode("utf-8")
    spaced = raw.hex(" ")
    return [("bytes", str(len(raw))), ("hex", spaced), ("\\x", "".join(f"\\x{b:02x}" for b in raw[:64])),
            ("bin", " ".join(f"{b:08b}" for b in raw[:16]) + (" …" if len(raw) > 16 else ""))]


def caesar(text: str, shift=None) -> list:
    """Shift ASCII letters. Without `shift` returns all 25 candidates (ROT13 first)."""
    text = (text or "")[:500]

    def rot(n: int) -> str:
        out = []
        for ch in text:
            if "a" <= ch <= "z":
                out.append(chr((ord(ch) - 97 + n) % 26 + 97))
            elif "A" <= ch <= "Z":
                out.append(chr((ord(ch) - 65 + n) % 26 + 65))
            else:
                out.append(ch)
        return "".join(out)
    if shift is not None:
        return [(f"+{shift % 26}", rot(shift % 26))]
    order = [13] + [n for n in range(1, 26) if n != 13]
    return [(f"+{n}" + (" (ROT13)" if n == 13 else ""), rot(n)) for n in order]


def entropy(text: str) -> dict:
    """Shannon entropy in bits per character plus a plain verdict key and a few shape hints."""
    s = (text or "")[:MAX_INPUT]
    n = len(s)
    if n == 0:
        return {}
    counts = Counter(s)
    bits = max(0.0, -sum(c / n * math.log2(c / n) for c in counts.values()))
    classes = {
        "lower": sum(c.islower() for c in s), "upper": sum(c.isupper() for c in s),
        "digits": sum(c.isdigit() for c in s), "symbols": sum((not c.isalnum()) and not c.isspace() for c in s),
        "non_ascii": sum(ord(c) > 127 for c in s),
    }
    shape = []
    if not re.search(r"\s", s) and len(s) >= 16:                           # shape hints only for a single token
        if re.fullmatch(r"[0-9a-fA-F]+", s) and len(counts) >= 6:
            shape.append("hex")
        elif re.fullmatch(r"[A-Za-z0-9+/_\-]+={0,2}", s):
            shape.append("base64")
    letters = sum(c.isalpha() for c in s) + s.count(" ")
    spaced = s.count(" ") >= max(1, n // 12) and letters / n >= 0.7        # prose has spaces and mostly letters
    if bits < 2.8:
        verdict = "repetitive"
    elif spaced and bits < 4.9:
        verdict = "natural"
    elif bits >= 4.0 and n >= 16:
        verdict = "random"
    else:
        verdict = "encoded"
    return {"length": n, "unique": len(counts), "bits": round(bits, 3), "max_bits": round(math.log2(len(counts)), 3) if len(counts) > 1 else 0.0,
            "total_bits": round(bits * n, 1), "classes": classes, "shape": shape, "verdict": verdict, "short": n < 16}
