"""Hash identification and small encoding utilities."""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
from urllib.parse import unquote

ALGOS = ("md5", "sha1", "sha256", "sha512", "sha3_256", "blake2b")


def digests(text: str) -> dict:
    data = text.encode("utf-8")
    return {a: hashlib.new(a, data).hexdigest() for a in ALGOS}


_PREFIXES = (
    (r"^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$", ["bcrypt"]),
    (r"^\$argon2(id|i|d)\$", ["Argon2"]),
    (r"^\$6\$", ["sha512crypt (Linux)"]),
    (r"^\$5\$", ["sha256crypt (Linux)"]),
    (r"^\$1\$", ["md5crypt (legacy)"]),
    (r"^\$apr1\$", ["Apache apr1 (md5)"]),
    (r"^\$y\$", ["yescrypt (Linux)"]),
    (r"^pbkdf2[_-]sha(1|256|512)\$", ["PBKDF2"]),
    (r"^\{SSHA\}", ["Salted SHA-1 (LDAP)"]),
    (r"^[a-f0-9]{16}$", ["MySQL323 / half-MD5"]),
    (r"^\*[A-F0-9]{40}$", ["MySQL 4.1+ (sha1(sha1))"]),
)
_BY_LEN = {32: ["MD5", "NTLM", "MD4"], 40: ["SHA-1", "RIPEMD-160"], 56: ["SHA-224", "SHA3-224"],
           64: ["SHA-256", "SHA3-256", "BLAKE2s"], 96: ["SHA-384", "SHA3-384"],
           128: ["SHA-512", "SHA3-512", "Whirlpool", "BLAKE2b"]}
WEAK = {"MD5", "NTLM", "MD4", "SHA-1", "MySQL323 / half-MD5", "md5crypt (legacy)", "Apache apr1 (md5)",
        "MySQL 4.1+ (sha1(sha1))"}


def identify(h: str) -> list:
    """Candidate algorithms for a hash string (best-effort, order = likelihood)."""
    h = h.strip()
    for pat, names in _PREFIXES:
        if re.match(pat, h, re.I if pat.startswith("^[a-f") else 0):
            return names
    if re.fullmatch(r"[a-fA-F0-9]+", h):
        return _BY_LEN.get(len(h), [])
    return []


def looks_like_hash(s: str) -> bool:
    return bool(identify(s))


def b64_decode(s: str) -> str | None:
    s = re.sub(r"\s+", "", s)
    s += "=" * (-len(s) % 4)
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return fn(s).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            continue
    return None


def b64_encode(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode()


def hex_decode(s: str) -> str | None:
    try:
        return bytes.fromhex(re.sub(r"[\s:]|0x", "", s)).decode("utf-8", "replace")
    except ValueError:
        return None


def url_decode(s: str) -> str:
    return unquote(s)
