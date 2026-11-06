from __future__ import annotations

import html
import logging
import re
import threading
import zipfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .ai_client import AIClient, APIError
from .config import Config
from .brand import CORE_PROMPT, DETAIL_PROMPTS
from .hardening import SAFETY_TAIL, KeyedLocks, PendingStore
from .i18n import t
from .personas import PERSONAS, SUMMARY_SYSTEM, TRANSLATOR_PROMPT
from .render import StreamRenderer, Typing
from .security.secrets_guard import redact
from . import __version__
from .access import GROUP_MEMBER_CMDS, AccessMixin
from .admin_panel import AdminPanelMixin
from .toolbox import ToolboxMixin
from .security_cmds import REPLY_ARG_CMDS, SecurityCommands
from .storage import Storage
from .telegram import TelegramAPI
from . import files as F
from .web_files import WebFilesMixin
from .workspace import WorkspaceMixin
from .ui import UIMixin, kb  # noqa: F401  (kb is re-exported for older imports)
from .utils import RateLimiter, est_tokens, fmt_duration, parse_duration

log = logging.getLogger("bot.app")

TEXT_EXT = (".txt", ".md", ".py", ".js", ".ts", ".json", ".csv", ".log", ".html", ".css",
            ".xml", ".yml", ".yaml", ".ini", ".sh", ".c", ".cpp", ".java", ".go", ".rs", ".sql", ".tsv",
            ".conf", ".cfg", ".toml", ".php", ".rb", ".ps1", ".bat", ".tf", ".rules", ".yar", ".eml", ".har", ".kt", ".swift",
            ".gradle", ".properties", ".htaccess", ".nginx", ".service", ".pcap.txt")
GROUP_NOTE = ("GROUP CHAT: you are answering a question asked inside a Telegram group. Answer the question directly "
              "and accurately in at most ~1200 characters, in the language of the question, with no menus and no "
              "follow-up questions unless essential. Keep a professional tone suitable for many readers.")
MAX_FILE_KB = 200
MAX_ZIP_KB = 3000
TEMPS = [0.2, 0.5, 0.7, 1.0, 1.3]

COMMANDS_AR = [("menu", "القائمة الرئيسية"), ("case", "القضايا (مساحات عمل)"), ("notes", "مكتبتي (ملاحظات)"),
               ("search", "بحث في الويب"), ("files", "تصدير ملفات / ZIP"), ("new", "محادثة جديدة"), ("stop", "إيقاف الرد"), ("help", "المساعدة")]
COMMANDS_EN = [("menu", "Main menu"), ("case", "Cases (workspaces)"), ("notes", "My library (notes)"),
               ("search", "Web search"), ("files", "Export files / ZIP"), ("new", "New conversation"), ("stop", "Stop reply"), ("help", "Help")]
# Older slash commands (/url, /ioc, /remind ...) still work as hidden shortcuts; they are just not advertised.


MAX_FACTS = 30
MAX_REMINDERS = 20
MAX_REMIND_SECONDS = 30 * 86400


def tr_(lang: str, ar: str, en: str) -> str:
    return ar if lang == "ar" else en


def _untag(h: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", h))


class Cancelled(Exception):
    """Raised inside the stream callback when the user sends /stop."""


class BotApp(UIMixin, AdminPanelMixin, AccessMixin, WebFilesMixin, ToolboxMixin, SecurityCommands, WorkspaceMixin):
    def __init__(self, cfg: Config, tg: TelegramAPI, ai: AIClient, db: Storage):
        self.cfg, self.tg, self.ai, self.db = cfg, tg, ai, db
        self.pool = ThreadPoolExecutor(max_workers=cfg.workers, thread_name_prefix="worker")
        self.locks = KeyedLocks()                      # one in-flight answer per chat (bounded memory)
        self.pending = PendingStore()                  # chat/user -> what the last button press is waiting for
        self.dm_target = {}                            # admin id -> user id awaiting a direct message
        self.drafts = {}                               # admin broadcast drafts awaiting confirmation
        self.hints = {}                                # (chat, user) -> message id of the "send me the input" prompt
        self.started = time.time()
        self._init_access()
        self._denied_shown = {}
        self.maintenance = False                       # admin switch: only admins are served while True
        self._key_notified = {}                        # masked key -> last admin notification time
        ai.pool.on_event = self._key_event
        self._eph = []                                 # (due, chat_id, message_id) auto-delete queue
        self._eph_mu = threading.Lock()
        self.limiter = RateLimiter(cfg.rate_limit, 60)
        self.stop = threading.Event()
        self.cancels = {}                              # chat_id -> Event (for /stop)
        self.bot_username = ""
        self.ctx = threading.local()                   # per-update context (message id for /pass cleanup)
        self._denied_seen = set()
        self.commands = {
            "start": self.cmd_start, "help": self.cmd_help, "menu": self.cmd_menu,
            "new": self.cmd_new, "reset": self.cmd_new, "retry": self.cmd_retry,
            "persona": self.cmd_persona, "temp": self.cmd_temp, "lang": self.cmd_lang,
            "system": self.cmd_system, "export": self.cmd_export, "usage": self.cmd_usage,
            "ask": self.cmd_ask, "stop": self.cmd_stop, "summary": self.cmd_summary, "tr": self.cmd_tr,
            "remember": self.cmd_remember, "memory": self.cmd_memory, "forget": self.cmd_forget,
            "remind": self.cmd_remind, "reminders": self.cmd_reminders, "unremind": self.cmd_unremind,
            "quota": self.cmd_quota, "detail": self.cmd_detail,
        }
        self.commands.update(self.security_commands())
        self.commands.update(self.workspace_commands())
        self.commands.update(self.web_files_commands())
        self.commands.update(self.toolbox_commands())
        self.commands.update({"groupusage": self.cmd_groupusage, "panel": self.cmd_panel})
        self.admin_commands = {
            "stats": self.adm_stats, "users": self.adm_users, "broadcast": self.adm_broadcast,
            "ban": self.adm_ban, "unban": self.adm_unban, "allow": self.adm_allow,
            "disallow": self.adm_disallow, "backup": self.adm_backup, "audit": self.adm_audit,
            "status": self.adm_status, "keys": self.adm_keys, "diag": self.adm_diag,
            "find": self.adm_find, "dm": self.adm_dm_send, "dmq": self.adm_dm_pending,
        }

    # ------------------------------------------------------------------ lifecycle
    def setup(self) -> None:
        me = self.tg.get_me()
        if not me:
            raise RuntimeError("Telegram getMe failed — check TELEGRAM_TOKEN / network")
        self.bot_username = me.get("username", "")
        self.bot_id = int(me.get("id") or 0)
        self.can_read_all = bool(me.get("can_read_all_group_messages", True))
        if self.cfg.groups and not self.can_read_all:
            log.warning("Privacy Mode is ON: in groups the bot only sees /commands, @mentions and replies. For the "
                        "\"DZ <question>\" trigger disable it in @BotFather (/setprivacy) or make the bot a group admin.")
        log.info("Bot @%s started (model=%s)", self.bot_username, self.cfg.model)
        threading.Thread(target=self._scheduler, daemon=True, name="scheduler").start()
        self.tg.delete_webhook()
        self.tg.set_my_commands([{"command": c, "description": d} for c, d in COMMANDS_AR])
        self.tg.set_my_commands([{"command": c, "description": d} for c, d in COMMANDS_EN], "en")
        if not (self.cfg.public or self.cfg.admin_ids or self.cfg.allowed_ids):
            log.warning("Nobody can use the bot: set ADMIN_IDS, ALLOWED_IDS or PUBLIC=true "
                        "(send /id to the bot to learn your ID)")

    def run(self) -> None:
        self.setup()
        offset, backoff = None, 1
        while not self.stop.is_set():
            updates = self.tg.get_updates(offset)
            if updates is None:
                self.stop.wait(backoff)
                backoff = min(backoff * 2, 30)
                continue
            backoff = 1
            for upd in updates:
                offset = upd["update_id"] + 1
                self.pool.submit(self._safe, upd)
        log.info("Shutting down…")
        self.pool.shutdown(wait=True, cancel_futures=False)

    def _safe(self, upd) -> None:
        try:
            if "message" in upd:
                self.on_message(upd["message"])
            elif "callback_query" in upd:
                self.on_callback(upd["callback_query"])
            elif "my_chat_member" in upd:
                self.on_my_chat_member(upd["my_chat_member"])
        except Exception:
            log.exception("update handling failed")

    # ------------------------------------------------------------------ access
    def is_admin(self, uid) -> bool:
        return uid in self.cfg.admin_ids

    def allowed(self, user: dict) -> bool:
        uid = user["id"]
        if user["banned"] and not self.is_admin(uid):
            return False
        if self.is_admin(uid) or self.cfg.public:
            return True
        if uid in self.cfg.allowed_ids or user.get("role") == "mod":      # moderators always have access
            return True
        if user["allowed"]:
            exp = user.get("expires_at") or 0
            if exp and exp < time.time():                       # temporary access ended
                self.db.set_user(uid, allowed=0, expires_at=0)
                user["allowed"], user["expires_at"] = 0, 0
                self.db.add_audit(uid, "access_expired", "")
                return False
            return True
        return False

    def _user(self, frm: dict) -> dict:
        return self.db.upsert_user(frm["id"], frm.get("username"), frm.get("first_name"),
                                   self.cfg.default_lang, self.cfg.default_temp)

    # ------------------------------------------------------------------ message flow
    def on_message(self, msg: dict) -> None:
        ctype = msg["chat"].get("type")
        is_group = ctype in ("group", "supergroup")
        if ctype != "private" and not (is_group and self.cfg.groups):
            return
        if is_group and self.bot_id and any(m.get("id") == self.bot_id for m in msg.get("new_chat_members") or []):
            self.group_joined(msg["chat"], msg.get("from"))     # fallback for the my_chat_member update
            return
        frm = msg.get("from") or {}
        if not frm or frm.get("is_bot"):
            return
        chat_id, uid = msg["chat"]["id"], frm["id"]
        self.ctx.msg_id = msg.get("message_id")
        self.ctx.after_kb = None
        self._reset_ctx()
        user = self._user(frm)
        lang = user["lang"]
        text = (msg.get("text") or "").strip()
        member_ok = False
        if is_group:
            text = self._group_text(msg, text)
            if text is None:
                return
            head = text.split()[0][1:].split("@")[0].lower() if text.startswith("/") else ""
            if head in ("allowgroup", "revokegroup"):
                self.group_admin_command(chat_id, msg, uid, head)
                return
            member_ok = self.group_member_ok(chat_id, msg, user)

        if text.startswith("/"):
            head, _, args = text.partition(" ")
            cmd = head[1:].split("@")[0].lower()
            args = args.strip()
            if cmd == "id":
                self.tg.send_message(chat_id, f"🆔 {uid}")
                return
            personal = self.allowed(user)
            if not personal and not (member_ok and cmd in GROUP_MEMBER_CMDS):
                self._deny(chat_id, user, is_group)
                return
            if self._under_maintenance(chat_id, user):
                return
            if self.pending.pop(chat_id, uid):              # a typed command cancels any pending button input
                self._clear_hint(chat_id, uid)
            if not args and cmd in REPLY_ARG_CMDS:
                args = self._replied_text(msg)
            if cmd in self.commands:
                self.commands[cmd](chat_id, user, args)
                return
            if cmd in self.admin_commands:
                if not self.is_admin(uid):
                    self.tg.send_message(chat_id, t(lang, "admin_only"))
                    return
                if chat_id < 0:                              # a group would see backups, user lists and the audit log
                    self.tg.send_message(chat_id, tr_(lang, "🔒 أوامر المدير تعمل في المحادثة الخاصة فقط.",
                                                      "🔒 Admin commands work in private chat only."))
                    return
                self.admin_commands[cmd](chat_id, user, args)
                return
            if not is_group:
                self.tg.send_message(chat_id, t(lang, "unknown_cmd"),
                                     kb([[("🏠 " + tr_(lang, "القائمة", "Menu"), "m:main")]]))
            return

        if not self.allowed(user) and not member_ok:
            self._deny(chat_id, user, is_group)
            return
        if self._under_maintenance(chat_id, user):
            return

        kind = self.pending.pop(chat_id, uid)
        if msg.get("document"):
            text = self._read_document(chat_id, user, msg, raw=bool(kind))
            if text is None:
                if kind:
                    self.pending.set(chat_id, uid, kind)    # bad file: keep waiting for valid input
                return
        elif msg.get("caption") and not text:
            text = msg["caption"].strip()
        if not text:
            if kind:
                self.pending.set(chat_id, uid, kind)        # keep waiting
            self.tg.send_message(chat_id, t(lang, "unsupported"))
            return
        if kind:
            self._clear_hint(chat_id, uid)                  # the prompt is answered: keep the chat tidy
            self.run_pending(chat_id, user, kind, text)
            return
        self.chat(chat_id, user, text)

    def _reset_ctx(self) -> None:
        """Pool threads are reused: never let a one-shot flag from a previous update leak into the next one."""
        self.ctx.web_force = False
        self.ctx.web_sources = []

    def _under_maintenance(self, chat_id, user) -> bool:
        if not self.maintenance or self.is_admin(user["id"]):
            return False
        if chat_id > 0:
            self.tg.send_message(chat_id, tr_(user["lang"], "🛠 البوت تحت الصيانة مؤقتاً، حاول بعد قليل.",
                                              "🛠 The bot is under maintenance, please try again shortly."))
        return True

    def _clear_hint(self, chat_id, uid) -> None:
        mid = self.hints.pop((chat_id, uid), None)
        if mid:
            self.tg.delete_message(chat_id, mid)

    def _deny(self, chat_id, user, is_group) -> None:
        uid = user["id"]
        if uid not in self._denied_seen:                # audit once per user per run, avoids log flooding
            self._denied_seen.add(uid)
            self.db.add_audit(uid, "denied", f"@{user.get('username') or '-'}")
        if not is_group:
            now = time.time()
            if now - self._denied_shown.get(uid, 0) >= 20:       # never let a stranger make the bot flood the chat
                self._denied_shown[uid] = now
                self.show_access(chat_id, user)

    @staticmethod
    def _replied_text(msg: dict) -> str:
        r = msg.get("reply_to_message") or {}
        return (r.get("text") or r.get("caption") or "").strip()

    def _guard(self, chat_id, user, text: str) -> str:
        """Mask credentials before storage / sending to the model; warn the user once per message."""
        if not self.cfg.secret_guard:
            return text
        clean, kinds = redact(text)
        if kinds:
            self.db.add_audit(user["id"], "secret_masked", ",".join(kinds))
            self.tg.send_message(chat_id, t(user["lang"], "secret_warn", k=", ".join(kinds)))
            mid = getattr(self.ctx, "msg_id", None)
            if mid and chat_id > 0:                     # private chat: remove the original message containing the secret
                self.tg.delete_message(chat_id, mid)
        return clean

    def _group_text(self, msg: dict, text: str):
        """In groups: react only to commands for this bot, @mentions, and replies to the bot."""
        me = self.bot_username.lower()
        if text.startswith("/"):
            head = text.split()[0]
            if "@" in head and head.split("@", 1)[1].lower() != me:
                return None
            return text
        trig = self.group_trigger(text)
        if trig is not None:                                    # "DZ <question>"
            return trig or "/groupusage"
        if me and f"@{me}" in text.lower():
            return re.sub(re.escape(f"@{me}"), "", text, flags=re.I).strip() or None
        replied_to = ((msg.get("reply_to_message") or {}).get("from") or {}).get("username", "")
        if me and replied_to.lower() == me:
            return text or None
        return None

    def _read_document(self, chat_id, user, msg, raw=False):
        lang, doc = user["lang"], msg["document"]
        name = (doc.get("file_name") or "file").lower()
        mime = doc.get("mime_type") or ""
        is_zip = name.endswith(".zip") or mime in ("application/zip", "application/x-zip-compressed")
        if not (is_zip or mime.startswith("text/") or name.endswith(TEXT_EXT) or mime in ("application/json", "application/xml")):
            self.tg.send_message(chat_id, t(lang, "file_bad"))
            return None
        max_kb = MAX_ZIP_KB if is_zip else MAX_FILE_KB
        if (doc.get("file_size") or 0) > max_kb * 1024:
            self.tg.send_message(chat_id, t(lang, "file_too_big", n=max_kb))
            return None
        data = self.tg.get_file_bytes(doc["file_id"], max_kb * 1024)
        if data is None:
            self.tg.send_message(chat_id, t(lang, "err_generic", e="download failed"))
            return None
        if is_zip:
            try:
                body = F.read_zip_project(data)
            except (ValueError, zipfile.BadZipFile):
                self.tg.send_message(chat_id, tr_(lang, "📦 تعذّرت قراءة الأرشيف (تالف أو كبير أو غير آمن).",
                                                  "📦 Could not read the archive (corrupt, too large or unsafe)."))
                return None
        else:
            body = data.decode("utf-8", "replace")
        limit = self.cfg.max_input_chars * 3
        if len(body) > limit:
            body = body[:limit] + "\n…[truncated]"
        if raw:                                     # tool input: only the file body, no wrapper prompt
            return body
        instr = (msg.get("caption") or "").strip() or t(lang, "file_default_prompt")
        return f"{instr}\n\n--- {doc.get('file_name', 'file')} ---\n{body}"

    # ------------------------------------------------------------------ AI
    def _quota_ok(self, chat_id, user) -> bool:
        ov = user.get("limit_override", -1)
        lim = ov if (ov is not None and ov >= 0) else self.cfg.daily_limit        # per-user override set by an admin
        if chat_id < 0 and not self.allowed(user) and self.cfg.group_member_limit:
            lim = self.cfg.group_member_limit                                     # members of an authorised group
        if lim and not self.is_admin(user["id"]) and self.db.daily_count(user["id"]) >= lim:
            self.tg.send_message(chat_id, t(user["lang"], "quota_hit", n=lim))
            return False
        return True

    def chat(self, chat_id, user, text) -> None:
        lang = user["lang"]
        if not self.limiter.allow(user["id"]):
            self.tg.send_message(chat_id, t(lang, "rate"))
            return
        if len(text) > self.cfg.max_input_chars * 4:
            self.tg.send_message(chat_id, t(lang, "too_long", n=self.cfg.max_input_chars * 4))
            return
        if not self._quota_ok(chat_id, user):
            return
        text = self._guard(chat_id, user, text)
        with self.locks[chat_id]:
            self.db.add_message(self._hk(chat_id, user), "user", text)
            self._answer(chat_id, user)

    def _build_messages(self, chat_id, user) -> list:
        persona = PERSONAS.get(user["persona"]) or PERSONAS[self.cfg.default_persona if self.cfg.default_persona in PERSONAS else "default"]
        facts = self.db.list_facts(user["id"])
        facts_txt = ("Things the user asked you to remember:\n" + "\n".join(f"- {f['text']}" for f in facts)) if facts else ""
        style = DETAIL_PROMPTS.get(user.get("detail") or "balanced", "") if persona.get("core") else ""
        case_txt = ""
        if user.get("case_id") and chat_id == user["id"]:
            c = self.db.get_case(user["id"], user["case_id"])
            if c:
                case_txt = (f"Current workspace (case): {c['name']}. Keep answers consistent with this engagement and "
                            "its earlier messages.")
        group_txt = GROUP_NOTE if chat_id < 0 else ""
        parts = [CORE_PROMPT if persona.get("core") else "", self.cfg.system_prompt, persona["prompt"], style,
                 user["custom_prompt"], facts_txt, case_txt, group_txt, SAFETY_TAIL if persona.get("core") else ""]
        system = "\n\n".join(p for p in parts if p)
        hist = self.db.get_history(self._hk(chat_id, user), self.cfg.max_history)
        kept, total = [], 0
        for m in reversed(hist):
            total += len(m["content"])
            if total > self.cfg.max_context_chars and kept:
                break
            kept.append({"role": m["role"], "content": m["content"]})
        kept.reverse()
        return ([{"role": "system", "content": system}] if system else []) + kept

    @staticmethod
    def _err_text(lang, e: APIError) -> str:
        if e.status in (401, 402, 403, 429):
            return t(lang, f"err_{e.status if e.status != 403 else 401}")
        return t(lang, "err_generic", e=(e.message or "")[:200])

    def _record_usage(self, uid, usage) -> None:
        self.db.add_usage(uid, int(usage.get("prompt_tokens", 0)), int(usage.get("completion_tokens", 0)))
        self.db.bump_daily(uid)

    def _generate(self, chat_id, user, messages, temperature):
        """Stream one model reply into the chat. Returns the (possibly partial) text, or None when nothing usable."""
        lang = user["lang"]
        renderer = StreamRenderer(self.tg, chat_id, self.cfg.stream_interval, stop_markup=self.stop_kb(lang),
                                  final_markup=None if chat_id < 0 else self.answer_kb(lang),
                                  reply_to=getattr(self.ctx, "msg_id", None) if chat_id < 0 else None)
        cancel = threading.Event()
        self.cancels[chat_id] = cancel
        seen = [""]

        def on_delta(full):
            seen[0] = full
            if cancel.is_set():
                raise Cancelled()
            renderer.update(full)

        try:
            with Typing(self.tg, chat_id):
                text, usage = self.ai.chat(messages, temperature=temperature, stream=self.cfg.stream,
                                           on_delta=on_delta if self.cfg.stream else None)
        except Cancelled:
            text = seen[0]
            if not text.strip():
                renderer.fail("⏹", self.retry_kb(lang))
                return None
            renderer.finish(text + " ⏹")
            self._record_usage(user["id"], {
                "prompt_tokens": sum(len(m["content"]) for m in messages) // 3,
                "completion_tokens": est_tokens(text)})
            return text
        except APIError as e:
            log.warning("AI error %s: %s", e.status, e.message)
            renderer.fail(self._err_text(lang, e), self.retry_kb(lang))
            return None
        except Exception:
            log.exception("AI call crashed")           # never leave the user staring at "…"
            renderer.fail(t(lang, "err_generic", e="internal error"), self.retry_kb(lang))
            return None
        finally:
            self.cancels.pop(chat_id, None)
        renderer.finish(text)
        self._record_usage(user["id"], usage)
        return text

    def _answer(self, chat_id, user) -> None:
        web = self.web_context(chat_id, user)                       # "" unless the question needs fresh web data
        messages = self._build_messages(chat_id, user)
        if web:                                                     # untrusted data goes into the system block
            if messages and messages[0]["role"] == "system":
                messages[0] = {"role": "system", "content": messages[0]["content"] + "\n\n" + web}
            else:
                messages.insert(0, {"role": "system", "content": web})
        text = self._generate(chat_id, user, messages, user["temperature"])
        if text:
            self.db.add_message(self._hk(chat_id, user), "assistant", text)
            self.send_sources(chat_id, user)

    def _oneshot(self, chat_id, user, system, content, with_history=False, temperature=0.3, remember=False) -> None:
        """Single request. Not stored in the history unless `remember=True` (so follow-ups work)."""
        lang = user["lang"]
        if not self.limiter.allow(user["id"]):          # rate-limit first: do not mask/delete for a refused request
            self.tg.send_message(chat_id, t(lang, "rate"))
            return
        if not self._quota_ok(chat_id, user):
            return
        content = self._guard(chat_id, user, content)
        with self.locks[chat_id]:
            msgs = [{"role": "system", "content": system + ("\n\n" + SAFETY_TAIL if system == CORE_PROMPT else "")}]
            if with_history:
                msgs += [{"role": m["role"], "content": m["content"]}
                         for m in self.db.get_history(self._hk(chat_id, user), self.cfg.max_history)]
            msgs.append({"role": "user", "content": content})
            text = self._generate(chat_id, user, msgs, temperature)
            if text and remember:
                self.db.add_message(self._hk(chat_id, user), "user", content)
                self.db.add_message(self._hk(chat_id, user), "assistant", text)

    # ------------------------------------------------------------------ user commands
    def cmd_start(self, chat_id, user, args):
        name = html.escape(user.get("first_name") or "", quote=False)
        self.tg.send_rich(chat_id, t(user["lang"], "welcome", name=name), _untag(t(user["lang"], "welcome", name=name)),
                          self.main_menu(user["lang"], self.is_staff(user["id"])))

    def cmd_help(self, chat_id, user, args):
        text = t(user["lang"], "help") + tr_(
            user["lang"],
            "\n\n🔎 <b>بحث الويب</b>: /search سؤال · /web للتحكم (إيقاف / تلقائي / دائماً)\n"
            "📁 <b>الملفات</b>: زر «ملفات» تحت أي إجابة أو /files · /zip مشروع كامل · /save app.py نص\n📦 أرسل لي ملف ZIP لمشروعك وسأراجعه كاملاً.\n🧰 أدوات جديدة: /hex · /caesar · /entropy\n👥 في المجموعات: اكتب DZ ثم سؤالك.",
            "\n\n🔎 <b>Web search</b>: /search question · /web to control (off / auto / always)\n"
            "📁 <b>Files</b>: the “Files” button under any answer or /files · /zip full project · /save app.py text\n📦 Send me a ZIP of your project and I will review all of it.\n🧰 New tools: /hex · /caesar · /entropy\n👥 In groups: write DZ then your question.")
        if self.is_admin(user["id"]):
            text += t(user["lang"], "admin_help")
        self.tg.send_rich(chat_id, text, _untag(text), self.main_menu(user["lang"], self.is_staff(user["id"])))

    def cmd_menu(self, chat_id, user, args):
        self.show_main(chat_id, user)

    def cmd_new(self, chat_id, user, args):
        self.db.clear_history(self._hk(chat_id, user))
        self.tg.send_message(chat_id, t(user["lang"], "reset_ok"))

    def cmd_retry(self, chat_id, user, args):
        with self.locks[chat_id]:
            hk = self._hk(chat_id, user)
            last = self.db.pop_last_exchange(hk)
            if last is None:
                self.tg.send_message(chat_id, t(user["lang"], "nothing_retry"))
                return
            if not self._quota_ok(chat_id, user):
                self.db.add_message(hk, "user", last)
                return
            if not self.limiter.allow(user["id"]):
                self.db.add_message(hk, "user", last)
                self.tg.send_message(chat_id, t(user["lang"], "rate"))
                return
            self.db.add_message(hk, "user", last)
            self._answer(chat_id, user)

    def _persona_kb(self, lang):
        items = [(p[lang], f"persona:{k}") for k, p in PERSONAS.items()]
        return kb([items[i:i + 2] for i in range(0, len(items), 2)] + [self.home_row(lang)])

    def cmd_persona(self, chat_id, user, args):
        self.tg.send_message(chat_id, t(user["lang"], "persona_pick"), self._persona_kb(user["lang"]))

    def _temp_kb(self):
        return kb([[(str(v), f"temp:{v}") for v in TEMPS], [("🏠", "m:main")]])

    def cmd_temp(self, chat_id, user, args):
        if args:
            try:
                v = max(0.0, min(2.0, float(args)))
                self.db.set_user(user["id"], temperature=v)
                self.tg.send_message(chat_id, t(user["lang"], "temp_set", v=v))
                return
            except ValueError:
                pass
        self.tg.send_message(chat_id, t(user["lang"], "temp_pick"), self._temp_kb())

    def _lang_kb(self):
        return kb([[("🇸🇦 العربية", "lang:ar"), ("🇬🇧 English", "lang:en")], [("🏠", "m:main")]])

    def cmd_lang(self, chat_id, user, args):
        self.tg.send_message(chat_id, t(user["lang"], "lang_pick"), self._lang_kb())

    def cmd_system(self, chat_id, user, args):
        lang = user["lang"]
        if not args:
            cur = user["custom_prompt"]
            self.tg.send_message(chat_id, t(lang, "system_cur", p=cur) if cur else t(lang, "system_none"))
        elif args.lower() in ("off", "clear", "reset", "إلغاء"):
            self.db.set_user(user["id"], custom_prompt="")
            self.tg.send_message(chat_id, t(lang, "system_cleared"))
        else:
            self.db.set_user(user["id"], custom_prompt=(redact(args[:2000])[0] if self.cfg.secret_guard else args[:2000]))
            self.tg.send_message(chat_id, t(lang, "system_set"))

    def cmd_export(self, chat_id, user, args):
        hist = self.db.get_history(self._hk(chat_id, user), 500)
        if not hist:
            self.tg.send_message(chat_id, t(user["lang"], "export_empty"))
            return
        lines = []
        for m in hist:
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(m["ts"]))
            who = "You" if m["role"] == "user" else "AI"
            lines.append(f"[{when}] {who}:\n{m['content']}\n")
        self.tg.send_document(chat_id, "conversation.txt", "\n".join(lines).encode("utf-8"))

    def _cost(self, tin, tout) -> float:
        return tin / 1e6 * self.cfg.price_in + tout / 1e6 * self.cfg.price_out

    def cmd_usage(self, chat_id, user, args):
        u = self.db.get_user(user["id"])
        self.tg.send_message(chat_id, t(user["lang"], "usage", m=u["msgs"], ti=u["tokens_in"],
                                        to=u["tokens_out"], cost=self._cost(u["tokens_in"], u["tokens_out"])))

    # ------------------------------------------------------------------ extra commands
    def cmd_ask(self, chat_id, user, args):
        if not args:
            self.tg.send_message(chat_id, t(user["lang"], "ask_usage"))
            return
        self.chat(chat_id, user, args)

    def cmd_stop(self, chat_id, user, args):
        ev = self.cancels.get(chat_id)
        if ev:
            ev.set()
            self.tg.send_message(chat_id, t(user["lang"], "stop_ok"))
        else:
            self.tg.send_message(chat_id, t(user["lang"], "stop_none"))

    def cmd_summary(self, chat_id, user, args):
        if not self.db.get_history(self._hk(chat_id, user), 1):
            self.tg.send_message(chat_id, t(user["lang"], "export_empty"))
            return
        self._oneshot(chat_id, user, SUMMARY_SYSTEM, t(user["lang"], "summary_instr"),
                      with_history=True)

    def cmd_tr(self, chat_id, user, args):
        if not args:
            self.tg.send_message(chat_id, t(user["lang"], "tr_usage"))
            return
        self._oneshot(chat_id, user, TRANSLATOR_PROMPT, args, temperature=0.2)

    # ---- memory
    def cmd_remember(self, chat_id, user, args):
        lang = user["lang"]
        if not args:
            self.cmd_memory(chat_id, user, "")
            return
        fact = redact(args[:300])[0] if self.cfg.secret_guard else args[:300]
        if self.db.add_fact(user["id"], fact, MAX_FACTS):
            self.tg.send_message(chat_id, t(lang, "remembered", t=fact))
        else:
            self.tg.send_message(chat_id, t(lang, "mem_full", n=MAX_FACTS))

    def cmd_memory(self, chat_id, user, args):
        facts = self.db.list_facts(user["id"])
        if not facts:
            self.tg.send_message(chat_id, t(user["lang"], "memory_empty"))
            return
        lines = [t(user["lang"], "memory_head")] + [f"{f['id']}. {f['text']}" for f in facts]
        self.tg.send_message(chat_id, "\n".join(lines))

    def cmd_forget(self, chat_id, user, args):
        lang = user["lang"]
        if args.lower() in ("all", "الكل"):
            self.tg.send_message(chat_id, t(lang, "forgot_all", n=self.db.clear_facts(user["id"])))
        elif args.isdigit():
            ok = self.db.delete_fact(user["id"], int(args))
            self.tg.send_message(chat_id, t(lang, "forgot" if ok else "not_found"))
        else:
            self.tg.send_message(chat_id, t(lang, "forget_usage"))

    # ---- reminders
    def cmd_remind(self, chat_id, user, args):
        lang = user["lang"]
        when, _, text = args.partition(" ")
        secs = parse_duration(when) if when else None
        text = text.strip()
        if not secs or not text:
            self.tg.send_message(chat_id, t(lang, "remind_usage"))
            return
        secs = min(secs, MAX_REMIND_SECONDS)
        if self.db.count_pending(user["id"]) >= MAX_REMINDERS:
            self.tg.send_message(chat_id, t(lang, "remind_limit", n=MAX_REMINDERS))
            return
        if self.cfg.secret_guard:
            text = redact(text)[0]
        rid = self.db.add_reminder(user["id"], chat_id, int(time.time()) + secs, text[:500])
        self.tg.send_message(chat_id, t(lang, "remind_set", id=rid, d=fmt_duration(secs)))

    def cmd_reminders(self, chat_id, user, args):
        rows = self.db.list_reminders(user["id"])
        if not rows:
            self.tg.send_message(chat_id, t(user["lang"], "reminders_empty"))
            return
        now = int(time.time())
        lines = [t(user["lang"], "reminders_head")]
        lines += [f"#{r['id']} · {fmt_duration(r['due'] - now)} · {r['text']}" for r in rows]
        self.tg.send_message(chat_id, "\n".join(lines))

    def cmd_unremind(self, chat_id, user, args):
        lang = user["lang"]
        if not args.isdigit():
            self.tg.send_message(chat_id, t(lang, "unremind_usage"))
            return
        ok = self.db.delete_reminder(user["id"], int(args))
        self.tg.send_message(chat_id, t(lang, "done" if ok else "not_found"))

    def cmd_detail(self, chat_id, user, args):
        v = args.strip().lower()
        if v in DETAIL_PROMPTS:
            self.db.set_user(user["id"], detail=v)
            self.tg.send_message(chat_id, t(user["lang"], "detail_set", v=v))
            return
        self.show_detail(chat_id, user)

    def cmd_quota(self, chat_id, user, args):
        used, lim = self.db.daily_count(user["id"]), self.cfg.daily_limit
        key = "quota_info" if lim and not self.is_admin(user["id"]) else "quota_unlimited"
        self.tg.send_message(chat_id, t(user["lang"], key, used=used, limit=lim))

    def schedule_delete(self, chat_id, message_id, delay: float) -> None:
        with self._eph_mu:
            self._eph.append((time.monotonic() + delay, chat_id, message_id))

    def _purge(self) -> None:
        if self.cfg.retention_days > 0:
            n = self.db.purge_messages(int(time.time()) - self.cfg.retention_days * 86400)
            if n:
                log.info("retention: removed %d old messages", n)

    def _scheduler(self) -> None:
        last_purge = 0.0
        while not self.stop.wait(2):
            try:
                for r in self.db.due_reminders(int(time.time())):
                    self.db.finish_reminder(r["id"])
                    u = self.db.get_user(r["user_id"]) or {}
                    lg = u.get("lang", "ar")
                    self.tg.send_message(r["chat_id"], f"⏰ {r['text']}", kb([[
                        ("⏰ +10m", "rem:snz:10"), ("⏰ +1h", "rem:snz:60"), ("✅ " + tr_(lg, "تم", "Done"), "rem:ok")]]))
                now = time.monotonic()
                with self._eph_mu:
                    due = [x for x in self._eph if x[0] <= now]
                    self._eph = [x for x in self._eph if x[0] > now]
                for _, cid, mid in due:
                    self.tg.delete_message(cid, mid)
                if now - last_purge > 3600:
                    last_purge = now
                    self._purge()
            except Exception:
                log.exception("scheduler failed")

    # ------------------------------------------------------------------ admin commands
    def adm_stats(self, chat_id, user, args):
        s = self.db.stats()
        self.tg.send_message(chat_id, t(user["lang"], "stats", cost=self._cost(s["tokens_in"], s["tokens_out"]), **s))

    def _key_event(self, kind, key, status, available) -> None:
        """Called by the key pool: log it, and tell the admins when a key stops working (throttled)."""
        from .keypool import mask
        name, total = mask(key), len(self.ai.pool)
        log.warning("API key %s %s (status %s) — %d/%d keys available", name, kind, status, available, total)
        now = time.time()
        if kind == "down" and (status in (401, 402, 403) or available == 0):
            if now - self._key_notified.get(name, 0) < 600:
                return
            self._key_notified[name] = now
            self.db.add_audit(0, "key_down", f"{name} status={status}")
            for aid in self.cfg.admin_ids:
                self.tg.send_message(aid, (f"⚠️ مفتاح API {name} تعطّل (الحالة {status}). "
                                           f"المتاح الآن {available}/{total}. /keys للتفاصيل.") if available else
                                     f"🚨 كل مفاتيح API متعطلة ({total}). آخر خطأ: {name} ({status}). /keys")
        elif kind == "up" and self._key_notified.pop(name, None):
            for aid in self.cfg.admin_ids:
                self.tg.send_message(aid, f"✅ مفتاح API {name} عاد للعمل ({available}/{total}).")

    def adm_keys(self, chat_id, user, args):
        lang = user["lang"]
        rows = self.ai.pool.status()
        why = {401: "غير صالح/ملغى", 402: "الرصيد انتهى", 403: "ممنوع", 429: "حد المعدّل", 0: "خطأ شبكة/بث"}
        lines = [f"🔑 <b>{tr_(lang, 'مفاتيح API', 'API keys')}</b> — {sum(r['ok'] for r in rows)}/{len(rows)} "
                 f"{tr_(lang, 'متاح', 'available')} · {self.ai.pool.strategy}"]
        for i, r in enumerate(rows, 1):
            if r["ok"]:
                state = "🟢 " + ("نشط" if r["current"] else "جاهز") if lang == "ar" else \
                        "🟢 " + ("active" if r["current"] else "ready")
            else:
                reason = why.get(r["last"], str(r["last"]))
                state = f"🔴 {reason} · {tr_(lang, 'يُعاد بعد', 'retry in')} {fmt_duration(r['retry_in'])}"
            lines.append(f"{i}. <code>{html.escape(r['key'], quote=False)}</code> — {state}"
                         + (f" ({tr_(lang, 'إخفاقات', 'fails')}: {r['fails']})" if r["fails"] else ""))
        h = "\n".join(lines)
        self.tg.send_rich(chat_id, h, _untag(h), kb([[("🔄 " + tr_(lang, "تحديث", "Refresh"), "adm:keys")] +
                                                      self.home_row(lang)]))

    def adm_status(self, chat_id, user, args):
        try:
            size_kb = Path(self.cfg.db_path).stat().st_size // 1024
        except OSError:
            size_kb = 0
        up = fmt_duration(time.time() - self.started)
        busy = len(self.cancels)
        self.tg.send_message(chat_id, (
            f"🩺 DARWIN DZ v{__version__}\n"
            f"• {tr_(user['lang'], 'التشغيل', 'Uptime')}: {up}\n"
            f"• {tr_(user['lang'], 'ردود قيد التوليد', 'Replies in progress')}: {busy}/{self.cfg.workers}\n"
            f"• {tr_(user['lang'], 'تذكيرات معلّقة', 'Pending reminders')}: {self.db.pending_total()}\n"
            f"• {tr_(user['lang'], 'قاعدة البيانات', 'Database')}: {size_kb} KB\n"
            f"• Model: {self.cfg.model}\n"
            f"• {tr_(user['lang'], 'مفاتيح API المتاحة', 'API keys available')}: "
            f"{self.ai.pool.available()}/{len(self.ai.pool)}\n"
            f"• {tr_(user['lang'], 'الوصول', 'Access')}: {'PUBLIC' if self.cfg.public else 'private'}"))

    def adm_diag(self, chat_id, user, args):
        """Admin-only operational diagnostics; never expose credentials or secret values."""
        try:
            db_state = self.db.integrity_check()
        except Exception as exc:
            log.exception("database diagnostic failed")
            db_state = f"error ({type(exc).__name__})"
        key_rows = self.ai.pool.status()
        available = sum(1 for row in key_rows if row["ok"])
        try:
            db_bytes = Path(self.cfg.db_path).stat().st_size
        except OSError:
            db_bytes = 0
        lang = user["lang"]
        ok = db_state.lower() == "ok"
        lines = [
            f"🔎 DARWIN DZ v{__version__} — {tr_(lang, 'تشخيص النظام', 'System diagnostics')}",
            f"• SQLite: {'✅' if ok else '⚠️'} {db_state}",
            f"• {tr_(lang, 'حجم قاعدة البيانات', 'Database size')}: {db_bytes // 1024} KB",
            f"• {tr_(lang, 'مفاتيح API المتاحة', 'Available API keys')}: {available}/{len(key_rows)}",
            f"• {tr_(lang, 'العمال', 'Workers')}: {self.cfg.workers}",
            f"• {tr_(lang, 'المهام النشطة', 'Active replies')}: {len(self.cancels)}",
            f"• {tr_(lang, 'مدة التشغيل', 'Uptime')}: {fmt_duration(time.time() - self.started)}",
            f"• Python: {__import__('sys').version.split()[0]}",
        ]
        self.tg.send_message(chat_id, "\n".join(lines))

    def adm_users(self, chat_id, user, args):
        rows = []
        for u in self.db.list_users(20):
            flags = ("🚫" if u["banned"] else "") + ("✅" if u["allowed"] else "")
            rows.append(f"{u['id']} @{u['username'] or '-'} {u['first_name'] or ''} · {u['msgs']} {flags}")
        self.tg.send_message(chat_id, "\n".join(rows) or "—")

    def adm_broadcast(self, chat_id, user, args):
        if not args:
            self.tg.send_message(chat_id, t(user["lang"], "usage_arg", cmd="/broadcast").replace("<id>", "<text>"))
            return
        self.db.add_audit(user["id"], "broadcast", args[:60])
        ok = fail = 0
        for row in self.db.broadcast_users():
            if not self.allowed(row):                      # never message strangers who only pressed /start
                continue
            if self.tg.send_message(row["id"], args):
                ok += 1
            else:
                fail += 1
            time.sleep(0.06)
        self.tg.send_message(chat_id, t(user["lang"], "broadcast_sent", ok=ok, fail=fail))

    def _id_arg(self, chat_id, user, args, cmd):
        try:
            return int(args.split()[0])
        except (ValueError, IndexError):
            self.tg.send_message(chat_id, t(user["lang"], "usage_arg", cmd=cmd))
            return None

    def _set_flag(self, chat_id, user, args, cmd, **fields):
        uid = self._id_arg(chat_id, user, args, cmd)
        if uid is None:
            return
        if uid <= 0 or uid in self.cfg.admin_ids:
            self.tg.send_message(chat_id, tr_(user["lang"], "🛡 لا يمكن تعديل مدير أو معرّف غير صالح.",
                                              "🛡 Cannot modify an admin or an invalid ID."))
            return
        self.db.ensure_user_row(uid, self.cfg.default_lang, self.cfg.default_temp)
        self.db.set_user(uid, **fields)
        self.tg.send_message(chat_id, t(user["lang"], "done"))

    def adm_ban(self, chat_id, user, args):
        self._set_flag(chat_id, user, args, "/ban", banned=1)
        self.db.add_audit(user["id"], "ban", args[:40])

    def adm_unban(self, chat_id, user, args):
        self._set_flag(chat_id, user, args, "/unban", banned=0)
        self.db.add_audit(user["id"], "unban", args[:40])

    def adm_allow(self, chat_id, user, args):
        self._set_flag(chat_id, user, args, "/allow", allowed=1)
        self.db.add_audit(user["id"], "allow", args[:40])

    def adm_disallow(self, chat_id, user, args):
        self._set_flag(chat_id, user, args, "/disallow", allowed=0)
        self.db.add_audit(user["id"], "disallow", args[:40])

    def adm_audit(self, chat_id, user, args):
        rows = self.db.list_audit(25)
        lines = [t(user["lang"], "audit_head")] + [
            f"{time.strftime('%m-%d %H:%M', time.localtime(r['ts']))} · {r['user_id']} · {r['action']} {r['detail']}"
            for r in rows]
        self.send_long(chat_id, "\n".join(lines) if rows else "—")

    def adm_backup(self, chat_id, user, args):
        if chat_id < 0:                                     # never post the database into a group
            return
        self.db.add_audit(user["id"], "backup")
        name = time.strftime("bot-%Y%m%d-%H%M.db")
        self.tg.send_document(chat_id, name, self.db.backup_bytes(), caption=t(user["lang"], "backup_caption"))
