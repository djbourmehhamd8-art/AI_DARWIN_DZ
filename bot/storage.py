from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

USER_FIELDS = {"lang", "persona", "temperature", "custom_prompt", "banned", "allowed", "detail", "case_id", "web",
               "requested_at", "expires_at", "role", "limit_override"}

HIST_BASE = 10 ** 14          # synthetic chat ids for case histories (far outside Telegram's id range)


def case_key(case_id: int) -> int:
    """History key of a case: its conversation lives beside, never mixed with, the normal chat history."""
    return -(HIST_BASE + int(case_id))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT, first_name TEXT,
    lang TEXT NOT NULL DEFAULT 'ar',
    persona TEXT NOT NULL DEFAULT 'default',
    temperature REAL NOT NULL DEFAULT 0.7,
    custom_prompt TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT 'balanced',
    case_id INTEGER NOT NULL DEFAULT 0,
    web TEXT NOT NULL DEFAULT '',
    requested_at INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL DEFAULT 0,
    role TEXT NOT NULL DEFAULT '',
    limit_override INTEGER NOT NULL DEFAULT -1,
    banned INTEGER NOT NULL DEFAULT 0,
    allowed INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL,
    msgs INTEGER NOT NULL DEFAULT 0,
    tokens_in INTEGER NOT NULL DEFAULT 0,
    tokens_out INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS chats (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL DEFAULT '',
    allowed INTEGER NOT NULL DEFAULT 0,
    added_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_id, id);
CREATE TABLE IF NOT EXISTS facts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL, text TEXT NOT NULL, ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_facts_user ON facts(user_id);
CREATE TABLE IF NOT EXISTS reminders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL, chat_id INTEGER NOT NULL,
    due INTEGER NOT NULL, text TEXT NOT NULL, done INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_reminders_due ON reminders(done, due);
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL, name TEXT NOT NULL, ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cases_user ON cases(user_id);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL, case_id INTEGER NOT NULL DEFAULT 0,
    title TEXT NOT NULL, text TEXT NOT NULL, ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notes_user ON notes(user_id, case_id);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL, user_id INTEGER NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS daily (
    user_id INTEGER NOT NULL, day TEXT NOT NULL, n INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, day)
);
"""


class Storage:
    def __init__(self, path: str):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA temp_store=MEMORY")
            self._conn.executescript(SCHEMA)
            self._migrate()
            self._conn.commit()

    def _migrate(self) -> None:
        """Add columns introduced after the first release to databases created by older versions."""
        cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(users)")}
        if "detail" not in cols:
            self._conn.execute("ALTER TABLE users ADD COLUMN detail TEXT NOT NULL DEFAULT 'balanced'")
        if "web" not in cols:
            self._conn.execute("ALTER TABLE users ADD COLUMN web TEXT NOT NULL DEFAULT ''")
        if "case_id" not in cols:
            self._conn.execute("ALTER TABLE users ADD COLUMN case_id INTEGER NOT NULL DEFAULT 0")
        for col, ddl in (("requested_at", "INTEGER NOT NULL DEFAULT 0"), ("expires_at", "INTEGER NOT NULL DEFAULT 0"),
                         ("role", "TEXT NOT NULL DEFAULT ''"), ("limit_override", "INTEGER NOT NULL DEFAULT -1")):
            if col not in cols:
                self._conn.execute(f"ALTER TABLE users ADD COLUMN {col} {ddl}")   # fixed names above, never user text

    def last_assistant(self, chat_id):
        r = self._one("SELECT content FROM messages WHERE chat_id=? AND role='assistant' ORDER BY id DESC LIMIT 1",
                      (chat_id,))
        return r["content"] if r else None

    def pending_total(self) -> int:
        return self._one("SELECT COUNT(*) c FROM reminders WHERE done=0")["c"]

    def _exec(self, sql, params=()):
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def _all(self, sql, params=()):
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def _one(self, sql, params=()):
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    # ---- users
    def upsert_user(self, uid, username, first_name, lang="ar", temp=0.7) -> dict:
        now = int(time.time())
        self._exec(
            "INSERT INTO users(id, username, first_name, lang, temperature, created_at, last_seen) "
            "VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET username=excluded.username, "
            "first_name=excluded.first_name, last_seen=excluded.last_seen",
            (uid, username, first_name, lang, temp, now, now),
        )
        return self.get_user(uid)

    def get_user(self, uid):
        row = self._one("SELECT * FROM users WHERE id=?", (uid,))
        return dict(row) if row else None

    def set_user(self, uid, **fields) -> None:
        bad = set(fields) - USER_FIELDS
        if bad:
            raise ValueError(f"unknown fields: {bad}")
        if not fields:
            return
        cols = ", ".join(f"{k}=?" for k in fields)
        self._exec(f"UPDATE users SET {cols} WHERE id=?", (*fields.values(), uid))

    def ensure_user_row(self, uid, lang="ar", temp=0.7) -> None:
        now = int(time.time())
        self._exec(
            "INSERT OR IGNORE INTO users(id, lang, temperature, created_at, last_seen) VALUES(?,?,?,?,?)",
            (uid, lang, temp, now, now),
        )

    def add_usage(self, uid, tokens_in, tokens_out) -> None:
        self._exec(
            "UPDATE users SET msgs=msgs+1, tokens_in=tokens_in+?, tokens_out=tokens_out+? WHERE id=?",
            (tokens_in, tokens_out, uid),
        )

    _USER_FILTERS = {"": "", "banned": " WHERE banned=1", "allowed": " WHERE allowed=1",
                     "pending": " WHERE requested_at>0 AND allowed=0 AND banned=0",
                     "staff": " WHERE role<>''"}

    def list_users(self, limit=20, offset=0, where: str = "") -> list:
        """`where` is one of the fixed filters in _USER_FILTERS (never user text)."""
        rows = self._all("SELECT * FROM users" + self._USER_FILTERS[where] + " ORDER BY last_seen DESC LIMIT ? OFFSET ?",
                         (limit, max(0, offset)))
        return [dict(r) for r in rows]

    def count_users(self, where: str = "") -> int:
        """`where` is one of a fixed set of filters (never user text)."""
        return self._one("SELECT COUNT(*) n FROM users" + self._USER_FILTERS[where])["n"]

    def find_user(self, query: str):
        """Look a user up by numeric id or @username (exact, case-insensitive)."""
        q = (query or "").strip().lstrip("@")
        if not q:
            return None
        if q.lstrip("-").isdigit():
            r = self._one("SELECT * FROM users WHERE id=?", (int(q),))
        else:
            r = self._one("SELECT * FROM users WHERE LOWER(username)=LOWER(?)", (q,))
        return dict(r) if r else None

    def broadcast_ids(self) -> list:
        return [r["id"] for r in self._all("SELECT id FROM users WHERE banned=0")]

    def broadcast_users(self) -> list:
        return [dict(r) for r in self._all("SELECT * FROM users WHERE banned=0")]

    # ---- messages
    def add_message(self, chat_id, role, content, keep=200) -> None:
        with self._lock:                                    # one transaction: insert + trim
            self._conn.execute("INSERT INTO messages(chat_id, role, content, ts) VALUES(?,?,?,?)",
                               (chat_id, role, content, int(time.time())))
            self._conn.execute(
                "DELETE FROM messages WHERE chat_id=? AND id NOT IN "
                "(SELECT id FROM messages WHERE chat_id=? ORDER BY id DESC LIMIT ?)", (chat_id, chat_id, keep))
            self._conn.commit()

    def get_history(self, chat_id, limit=20) -> list:
        rows = self._all(
            "SELECT role, content, ts FROM messages WHERE chat_id=? ORDER BY id DESC LIMIT ?",
            (chat_id, limit),
        )
        return [dict(r) for r in reversed(rows)]

    def clear_history(self, chat_id) -> None:
        self._exec("DELETE FROM messages WHERE chat_id=?", (chat_id,))

    def pop_last_exchange(self, chat_id):
        """Remove trailing assistant replies and the last user message; return its text."""
        with self._lock:
            while True:
                row = self._one(
                    "SELECT id, role, content FROM messages WHERE chat_id=? ORDER BY id DESC LIMIT 1",
                    (chat_id,),
                )
                if row is None:
                    return None
                self._conn.execute("DELETE FROM messages WHERE id=?", (row["id"],))
                self._conn.commit()
                if row["role"] == "user":
                    return row["content"]

    def purge_messages(self, before_ts: int) -> int:
        """Retention: delete chat history older than `before_ts`."""
        return self._exec("DELETE FROM messages WHERE ts < ?", (before_ts,)).rowcount

    def wipe_user(self, uid, chat_id) -> dict:
        """Privacy: remove a user's history, memories, reminders and custom settings (ban/allow flags are kept)."""
        n_msg = self._exec("DELETE FROM messages WHERE chat_id=?", (chat_id,)).rowcount
        for c in self._all("SELECT id FROM cases WHERE user_id=?", (uid,)):
            n_msg += self._exec("DELETE FROM messages WHERE chat_id=?", (case_key(c["id"]),)).rowcount
        self._exec("DELETE FROM notes WHERE user_id=?", (uid,))
        self._exec("DELETE FROM cases WHERE user_id=?", (uid,))
        self._exec("UPDATE users SET case_id=0 WHERE id=?", (uid,))
        n_fact = self._exec("DELETE FROM facts WHERE user_id=?", (uid,)).rowcount
        n_rem = self._exec("DELETE FROM reminders WHERE user_id=?", (uid,)).rowcount
        self._exec("UPDATE users SET custom_prompt='', persona='default' WHERE id=?", (uid,))
        return {"messages": n_msg, "facts": n_fact, "reminders": n_rem}

    # ---- cases (separate workspaces with their own conversation and notes)
    def add_case(self, uid, name, max_n=10):
        with self._lock:
            if self._one("SELECT COUNT(*) c FROM cases WHERE user_id=?", (uid,))["c"] >= max_n:
                return None
            cur = self._conn.execute("INSERT INTO cases(user_id, name, ts) VALUES(?,?,?)",
                                     (uid, name[:60], int(time.time())))
            self._conn.commit()
            return cur.lastrowid

    def list_cases(self, uid) -> list:
        return [dict(r) for r in self._all("SELECT * FROM cases WHERE user_id=? ORDER BY id", (uid,))]

    def get_case(self, uid, cid):
        r = self._one("SELECT * FROM cases WHERE user_id=? AND id=?", (uid, cid))
        return dict(r) if r else None

    def delete_case(self, uid, cid) -> bool:
        with self._lock:
            if not self.get_case(uid, cid):
                return False
            self._conn.execute("DELETE FROM messages WHERE chat_id=?", (case_key(cid),))
            self._conn.execute("DELETE FROM notes WHERE user_id=? AND case_id=?", (uid, cid))
            self._conn.execute("DELETE FROM cases WHERE id=?", (cid,))
            self._conn.execute("UPDATE users SET case_id=0 WHERE id=? AND case_id=?", (uid, cid))
            self._conn.commit()
            return True

    # ---- notes (saved answers)
    def add_note(self, uid, case_id, title, text, max_n=100):
        with self._lock:
            if self._one("SELECT COUNT(*) c FROM notes WHERE user_id=?", (uid,))["c"] >= max_n:
                return None
            cur = self._conn.execute("INSERT INTO notes(user_id, case_id, title, text, ts) VALUES(?,?,?,?,?)",
                                     (uid, case_id, title[:80], text[:8000], int(time.time())))
            self._conn.commit()
            return cur.lastrowid

    def list_notes(self, uid, case_id, limit=5, offset=0, query=None) -> list:
        sql, args = "SELECT * FROM notes WHERE user_id=? AND case_id=?", [uid, case_id]
        if query:
            esc = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            sql += " AND (title LIKE ? ESCAPE '\\' OR text LIKE ? ESCAPE '\\')"
            args += [f"%{esc}%", f"%{esc}%"]
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        return [dict(r) for r in self._all(sql, (*args, limit, offset))]

    def count_notes(self, uid, case_id, query=None) -> int:
        if query:
            return len(self.list_notes(uid, case_id, limit=1000, query=query))
        return self._one("SELECT COUNT(*) c FROM notes WHERE user_id=? AND case_id=?", (uid, case_id))["c"]

    def count_all_notes(self, uid) -> int:
        return self._one("SELECT COUNT(*) c FROM notes WHERE user_id=?", (uid,))["c"]

    def get_note(self, uid, nid):
        r = self._one("SELECT * FROM notes WHERE user_id=? AND id=?", (uid, nid))
        return dict(r) if r else None

    def delete_note(self, uid, nid) -> bool:
        return self._exec("DELETE FROM notes WHERE user_id=? AND id=?", (uid, nid)).rowcount > 0

    # ---- stats
    def stats(self) -> dict:
        day = int(time.time()) - 86400
        r = self._one(
            "SELECT COUNT(*) n, COALESCE(SUM(msgs),0) m, COALESCE(SUM(tokens_in),0) ti, "
            "COALESCE(SUM(tokens_out),0) tout, "
            "COALESCE(SUM(CASE WHEN last_seen>? THEN 1 ELSE 0 END),0) active, "
            "COALESCE(SUM(banned),0) banned FROM users",
            (day,),
        )
        return {
            "users": r["n"], "msgs": r["m"], "tokens_in": r["ti"],
            "tokens_out": r["tout"], "active24": r["active"], "banned": r["banned"],
        }

    def top_users(self, n=10) -> list:
        return [dict(r) for r in self._all("SELECT * FROM users ORDER BY msgs DESC, tokens_out DESC LIMIT ?", (n,))]

    # ---- groups (a group must be authorised by an admin before the bot answers its members)
    def upsert_chat(self, chat_id: int, title: str) -> dict:
        now = int(time.time())
        self._exec("INSERT INTO chats(id, title, added_at, last_seen) VALUES(?,?,?,?) "
                   "ON CONFLICT(id) DO UPDATE SET title=excluded.title, last_seen=excluded.last_seen",
                   (chat_id, (title or "")[:120], now, now))
        return self.get_chat(chat_id)

    def get_chat(self, chat_id: int):
        r = self._one("SELECT * FROM chats WHERE id=?", (chat_id,))
        return dict(r) if r else None

    def set_chat_allowed(self, chat_id: int, allowed: bool) -> None:
        self._exec("UPDATE chats SET allowed=? WHERE id=?", (1 if allowed else 0, chat_id))

    def list_chats(self, limit=50, offset=0) -> list:
        return [dict(r) for r in self._all("SELECT * FROM chats ORDER BY allowed DESC, last_seen DESC LIMIT ? OFFSET ?",
                                           (limit, max(0, offset)))]

    def count_chats(self) -> int:
        return self._one("SELECT COUNT(*) n FROM chats")["n"]

    def delete_chat(self, chat_id: int) -> None:
        self._exec("DELETE FROM chats WHERE id=?", (chat_id,))

    # ---- facts (user memory)
    def add_fact(self, uid, text, max_n=30) -> bool:
        n = self._one("SELECT COUNT(*) c FROM facts WHERE user_id=?", (uid,))["c"]
        if n >= max_n:
            return False
        self._exec("INSERT INTO facts(user_id, text, ts) VALUES(?,?,?)", (uid, text, int(time.time())))
        return True

    def list_facts(self, uid) -> list:
        return [dict(r) for r in self._all("SELECT id, text FROM facts WHERE user_id=? ORDER BY id", (uid,))]

    def delete_fact(self, uid, fid) -> bool:
        return self._exec("DELETE FROM facts WHERE user_id=? AND id=?", (uid, fid)).rowcount > 0

    def clear_facts(self, uid) -> int:
        return self._exec("DELETE FROM facts WHERE user_id=?", (uid,)).rowcount

    # ---- reminders
    def add_reminder(self, uid, chat_id, due, text) -> int:
        return self._exec("INSERT INTO reminders(user_id, chat_id, due, text) VALUES(?,?,?,?)",
                          (uid, chat_id, due, text)).lastrowid

    def count_pending(self, uid) -> int:
        return self._one("SELECT COUNT(*) c FROM reminders WHERE user_id=? AND done=0", (uid,))["c"]

    def list_reminders(self, uid) -> list:
        return [dict(r) for r in self._all(
            "SELECT id, due, text FROM reminders WHERE user_id=? AND done=0 ORDER BY due", (uid,))]

    def delete_reminder(self, uid, rid) -> bool:
        return self._exec("UPDATE reminders SET done=1 WHERE user_id=? AND id=? AND done=0", (uid, rid)).rowcount > 0

    def due_reminders(self, now) -> list:
        return [dict(r) for r in self._all(
            "SELECT id, user_id, chat_id, text FROM reminders WHERE done=0 AND due<=? ORDER BY due", (now,))]

    def finish_reminder(self, rid) -> None:
        self._exec("UPDATE reminders SET done=1 WHERE id=?", (rid,))

    # ---- daily quota
    @staticmethod
    def _today() -> str:
        return time.strftime("%Y-%m-%d", time.gmtime())

    def bump_daily(self, uid) -> None:
        self._exec("INSERT INTO daily(user_id, day, n) VALUES(?,?,1) "
                   "ON CONFLICT(user_id, day) DO UPDATE SET n=n+1", (uid, self._today()))
        self._exec("DELETE FROM daily WHERE day < date('now','-7 day')")

    def daily_count(self, uid) -> int:
        r = self._one("SELECT n FROM daily WHERE user_id=? AND day=?", (uid, self._today()))
        return r["n"] if r else 0

    # ---- audit log (security-relevant events: admin actions, secret leaks blocked, denied access)
    def add_audit(self, uid, action, detail="", keep=2000) -> None:
        self._exec("INSERT INTO audit(ts, user_id, action, detail) VALUES(?,?,?,?)",
                   (int(time.time()), uid, action, detail[:300]))
        self._exec("DELETE FROM audit WHERE id <= (SELECT MAX(id) FROM audit) - ?", (keep,))

    def list_audit(self, limit=20) -> list:
        return [dict(r) for r in self._all("SELECT ts, user_id, action, detail FROM audit ORDER BY id DESC LIMIT ?", (limit,))]

    # ---- backup
    def backup_bytes(self) -> bytes:
        import os
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            dst = sqlite3.connect(path)
            with self._lock:
                self._conn.backup(dst)
            dst.close()
            return Path(path).read_bytes()
        finally:
            os.unlink(path)

    def integrity_check(self) -> str:
        """Run SQLite's lightweight integrity check and return its status."""
        with self._lock:
            row = self._conn.execute("PRAGMA quick_check").fetchone()
            return str(row[0]) if row else "unknown"

    def close(self) -> None:
        with self._lock:
            self._conn.close()
