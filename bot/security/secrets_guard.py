"""Detect and mask credentials before they are stored or sent to the AI backend."""
from __future__ import annotations

import re

PATTERNS = (
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S)),
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("telegram_token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{30,45}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("google_api", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe_key", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{20,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("sendgrid_key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("discord_token", re.compile(r"\b[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}\b")),
    ("azure_key", re.compile(r"(?i)\b(?:AccountKey|SharedAccessKey)=[A-Za-z0-9+/=]{20,}")),
    ("basic_auth", re.compile(r"(?i)\bbasic\s+[A-Za-z0-9+/]{16,}={0,2}")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}")),
    ("db_url_password", re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^\s:/@]+:)([^\s@/]{3,})(@)")),
    ("secret_assignment", re.compile(
        r"(?i)\b((?:api[_-]?key|secret|token|passwd|password|pwd|auth)[\w-]*\s*[:=]\s*['\"]?)([A-Za-z0-9_\-/.+=!@#$%^&*]{8,})")),
)


def redact(text: str):
    """Return (clean_text, sorted list of detected secret kinds)."""
    found = set()
    for kind, rx in PATTERNS:
        def sub(m, kind=kind):
            found.add(kind)
            if kind in ("db_url_password", "secret_assignment"):
                return f"{m.group(1)}[REDACTED:{kind}]" + (m.group(3) if kind == "db_url_password" else "")
            return f"[REDACTED:{kind}]"
        text = rx.sub(sub, text)
    return text, sorted(found)
