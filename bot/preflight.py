"""`python main.py --check`: verify the host is ready BEFORE starting the bot (config, database, Telegram, network).

Each check returns (status, label, detail) where status is "ok", "warn" or "fail". No AI request is made, so the
check costs nothing."""
from __future__ import annotations

import os
import socket
import sqlite3
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit


def _connect(host: str, port: int, timeout: float = 6.0, connect=socket.create_connection) -> None:
    connect((host, port), timeout).close()


def _default_web_probe(cfg):
    from . import websearch
    return websearch.search_web("how many countries are in the world", 2, brave_key=cfg.brave_api_key, searxng_url=cfg.searxng_url)


def run_preflight(cfg, tg=None, connect=socket.create_connection, web_probe=None) -> list:
    out = []

    def add(status, label, detail=""):
        out.append((status, label, detail))

    add("ok" if sys.version_info >= (3, 8) else "fail", "Python", sys.version.split()[0] + ("" if sys.version_info >= (3, 8) else " (need 3.8+)"))
    add("ok" if sqlite3.sqlite_version_info >= (3, 24) else "fail", "SQLite", sqlite3.sqlite_version + ("" if sqlite3.sqlite_version_info >= (3, 24) else " (need 3.24+)"))

    problems = cfg.validate()
    add("fail" if problems else "ok", "Configuration", "; ".join(problems) if problems else "valid")
    add("ok" if cfg.admin_ids else "warn", "ADMIN_IDS", f"{len(cfg.admin_ids)} admin(s)" if cfg.admin_ids else
        "none set: nobody can use the admin panel (send /id to the bot, then put the number in .env)")

    env = Path(".env")
    if env.exists():
        mode = env.stat().st_mode & 0o777
        add("ok" if not mode & 0o077 else "warn", ".env permissions", oct(mode) + ("" if not mode & 0o077 else "  → run: chmod 600 .env"))
    else:
        add("warn", ".env", "not found (using process environment only)")

    ddir = Path(cfg.db_path).parent
    try:
        ddir.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=ddir):
            pass
        add("ok", "Data folder writable", str(ddir))
    except OSError as e:
        add("fail", "Data folder writable", f"{ddir}: {e.strerror}")

    try:
        from .storage import Storage
        db = Storage(cfg.db_path)
        state = db.integrity_check()
        users = db.count_users()
        db.close()
        add("ok" if state.lower() == "ok" else "fail", "Database", f"integrity {state}, {users} user(s)")
    except Exception as e:                                           # noqa: BLE001
        add("fail", "Database", type(e).__name__)

    host = urlsplit(cfg.telegram_api_url).hostname or "api.telegram.org"
    try:
        _connect(host, 443 if cfg.telegram_api_url.startswith("https") else 80, connect=connect)
        add("ok", f"Network → {host}", "reachable")
    except OSError as e:
        add("fail", f"Network → {host}", e.strerror or type(e).__name__)
    if tg is not None:
        me = tg.get_me()
        if me:
            note = "" if me.get("can_read_all_group_messages", True) else \
                " | Privacy Mode ON: group 'DZ …' messages need the bot to be a group admin (or /setprivacy → Disable)"
            add("warn" if note else "ok", "Telegram token", f"@{me.get('username')}{note}")
        else:
            add("fail", "Telegram token", "getMe failed: wrong TELEGRAM_TOKEN or no access to Telegram")

    ai = urlsplit(cfg.api_base_url)
    try:
        _connect(ai.hostname, ai.port or (443 if ai.scheme == "https" else 80), connect=connect)
        add("ok", f"Network → {ai.hostname}", "reachable (API keys are not tested, no request is sent)")
    except (OSError, TypeError) as e:
        add("fail", f"Network → {ai.hostname}", getattr(e, "strerror", None) or type(e).__name__)

    if cfg.web_search:
        try:
            res, provider, diag = (web_probe or _default_web_probe)(cfg)
        except Exception as e:                                       # noqa: BLE001
            res, provider, diag = [], "", [type(e).__name__]
        if res:
            add("ok" if provider in ("brave", "searxng", "duckduckgo", "duckduckgo-lite") else "warn", "Web search",
                f"works via {provider}" + ("" if provider != "wikipedia" else
                                           " (fallback only: DuckDuckGo is blocking this server; add BRAVE_API_KEY for reliable results)"))
        else:
            add("warn", "Web search", "no provider answered (" + "; ".join(diag)[:160] + "). Answers will skip web results. Add BRAVE_API_KEY (free) or SEARXNG_URL.")
    return out


def render(results: list) -> str:
    icons = {"ok": "✅", "warn": "⚠️", "fail": "❌"}
    lines = [f"{icons[s]} {label}" + (f" — {detail}" if detail else "") for s, label, detail in results]
    bad = sum(1 for s, _, _ in results if s == "fail")
    warn = sum(1 for s, _, _ in results if s == "warn")
    lines.append("")
    lines.append("RESULT: " + ("READY ✅" if not bad else f"NOT READY ❌ ({bad} problem(s))") + (f", {warn} warning(s)" if warn else ""))
    return "\n".join(lines)


def harden_data_permissions(cfg) -> None:
    """Best effort: data folder 700, database/log files 600 (they contain conversations)."""
    try:
        d = Path(cfg.db_path).parent
        if d.exists():
            os.chmod(d, 0o700)
        for base in (cfg.db_path, cfg.log_file):
            for suffix in ("", "-wal", "-shm"):
                p = Path(base + suffix)
                if p.exists():
                    os.chmod(p, 0o600)
    except OSError:
        pass
