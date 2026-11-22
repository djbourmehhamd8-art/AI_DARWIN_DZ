"""Layered decoding of obfuscated strings (base64 / hex / URL / ROT13) for analysts. Never executes anything."""
from __future__ import annotations

import base64
import binascii
import codecs
import re
from urllib.parse import unquote

MAX_LAYERS = 6


def _printable(b: bytes) -> str | None:
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not s.strip():
        return None
    bad = sum(1 for ch in s if ord(ch) < 32 and ch not in "\r\n\t")
    return s if bad / len(s) < 0.05 else None


def _try_b64(s: str):
    c = re.sub(r"\s+", "", s)
    if len(c) < 8 or not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", c):
        return None
    c += "=" * (-len(c) % 4)
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            out = _printable(fn(c))
        except (binascii.Error, ValueError):
            continue
        if out:
            return out
    return None


def _try_hex(s: str):
    c = re.sub(r"(?i)0x|\\x|[\s:,]", "", s)
    if len(c) < 8 or len(c) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", c):
        return None
    return _printable(bytes.fromhex(c))


def _try_url(s: str):
    out = unquote(s)
    return out if out != s and "%" in s else None


def decode_chain(s: str) -> list:
    """Return [(method, text), ...] applying successive decodings until nothing more decodes."""
    chain, cur = [], s.strip()
    for _ in range(MAX_LAYERS):
        for name, fn in (("url", _try_url), ("hex", _try_hex), ("base64", _try_b64)):
            out = fn(cur)
            if out and out != cur:
                chain.append((name, out))
                cur = out.strip()
                break
        else:
            break
    return chain


def rot13(s: str) -> str:
    return codecs.encode(s, "rot_13")
