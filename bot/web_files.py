"""Web-grounded answers and file export (TXT / MD / HTML / JSON / CSV / code files / ZIP)."""
from __future__ import annotations

import html
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor

from . import files as F
from . import websearch
from .formatting import to_html
from .security.secrets_guard import redact
from .ui import kb, tr

log = logging.getLogger("bot.webfiles")
VALID_WEB = ("off", "auto", "on")
MAX_SAVE_BYTES = 1_000_000
MAX_CODE_SENDS = 8


def _plain(h: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", h))


class WebFilesMixin:
    def web_files_commands(self) -> dict:
        return {"web": self.cmd_web, "search": self.cmd_search, "files": self.cmd_files,
                "zip": self.cmd_zip, "save": self.cmd_save}

    # ================================================================== web search
    def _web_mode(self, user) -> str:
        if not self.cfg.web_search:
            return "off"
        mode = (self.db.get_user(user["id"]) or user).get("web") or ""
        return mode if mode in VALID_WEB else self.cfg.web_default

    def _web_query(self, text: str) -> str:
        one = " ".join(text.split())
        if len(text) <= 100 and "\n" not in text.strip():
            q = one
        else:
            try:
                q, _ = self.ai.chat([
                    {"role": "system", "content": "Rewrite the user's message as ONE concise web search query "
                                                   "(max 12 words). Output only the query, nothing else."},
                    {"role": "user", "content": text[:1500]}], temperature=0, stream=False)
                q = (q or "").strip().strip("\"'`").splitlines()[0] if (q or "").strip() else one[:200]
            except Exception:                                         # noqa: BLE001
                q = one[:200]
        return redact(q[:300])[0]                                    # never send secrets to a search engine

    def web_context(self, chat_id, user) -> str:
        """Search the web for the latest user message when the mode asks for it; returns the system-prompt block."""
        force = bool(getattr(self.ctx, "web_force", False))
        self.ctx.web_force = False
        self.ctx.web_sources = []
        if not self.cfg.web_search:
            return ""
        mode = "on" if force else self._web_mode(user)
        hist = self.db.get_history(self._hk(chat_id, user), 6)
        last = next((m["content"] for m in reversed(hist) if m["role"] == "user"), "")
        if not websearch.should_search(last, mode):
            return ""
        lang = user["lang"]
        note = self.tg.send_message(chat_id, tr(lang, "🔎 أبحث في الويب…", "🔎 Searching the web…"))
        try:
            results = websearch.search(self._web_query(last), self.cfg.web_results)
            pages = {}
            if results and self.cfg.web_pages:
                top = results[:self.cfg.web_pages]
                with ThreadPoolExecutor(max_workers=len(top)) as ex:
                    for r, txt in zip(top, ex.map(lambda r: websearch.fetch_text(r["url"]), top)):
                        if txt:
                            pages[r["url"]] = txt
        finally:
            if note and note.get("message_id"):
                self.tg.delete_message(chat_id, note["message_id"])
        if not results:
            self.tg.send_message(chat_id, tr(lang, "🔎 تعذّر الوصول لنتائج الويب الآن، سأجيب من معرفتي.",
                                             "🔎 Web results are unavailable right now; answering from my own knowledge."))
            return ""
        self.ctx.web_sources = results
        return websearch.build_context(results, pages, time.strftime("%Y-%m-%d"))

    def send_sources(self, chat_id, user) -> None:
        results = getattr(self.ctx, "web_sources", None) or []
        self.ctx.web_sources = []
        if not results:
            return
        lines = [f'{i}. <a href="{html.escape(r["url"], quote=True)}">{html.escape(r["title"] or r["url"], quote=False)}</a>'
                 for i, r in enumerate(results, 1)]
        h = f"🔗 <b>{tr(user['lang'], 'المصادر', 'Sources')}</b>\n<blockquote expandable>" + "\n".join(lines) + "</blockquote>"
        self.tg.send_rich(chat_id, h, _plain(h))

    def show_web(self, chat_id, user, mid=None) -> None:
        lang = user["lang"]
        cur = self._web_mode(user)
        names = {"off": tr(lang, "⛔ إيقاف", "⛔ Off"), "auto": tr(lang, "🤖 تلقائي", "🤖 Auto"),
                 "on": tr(lang, "🌍 دائماً", "🌍 Always")}
        text = tr(lang, "🔎 <b>البحث في الويب</b>\n<blockquote>⛔ إيقاف — لا بحث\n🤖 تلقائي — أبحث عندما يحتاج السؤال معلومات حديثة "
                        "(أخبار، أسعار، إصدارات، CVE…)\n🌍 دائماً — أبحث مع كل سؤال</blockquote>\nنص سؤالك يُرسل لمحرك البحث بعد حجب الأسرار.",
                  "🔎 <b>Web search</b>\n<blockquote>⛔ Off — never\n🤖 Auto — when the question needs fresh info "
                  "(news, prices, versions, CVEs…)\n🌍 Always — every question</blockquote>\nYour question text is sent to the search engine after secrets are masked.")
        rows = [[((("✅ " if k == cur else "") + names[k]), f"web:{k}") for k in VALID_WEB],
                [("🏠 " + tr(lang, "القائمة", "Menu"), "m:main")]]
        self._html_screen(chat_id, mid, text, kb(rows))

    def cmd_web(self, chat_id, user, args) -> None:
        a = args.strip().lower()
        if a in VALID_WEB:
            self.db.set_user(user["id"], web=a)
            user = self.db.get_user(user["id"])
        self.show_web(chat_id, user)

    def cmd_search(self, chat_id, user, args) -> None:
        lang = user["lang"]
        if not self.cfg.web_search:
            self.tg.send_message(chat_id, tr(lang, "🔎 البحث في الويب معطّل من الإعدادات.", "🔎 Web search is disabled in the configuration."))
            return
        if not args.strip():
            self.ask(chat_id, user, "web_q")
            return
        self.ctx.web_force = True
        self.chat(chat_id, user, args.strip())

    # ================================================================== files
    def _last_answer(self, chat_id, user):
        return self.db.last_assistant(self._hk(chat_id, user))

    def _last_question(self, chat_id, user) -> str:
        hist = self.db.get_history(self._hk(chat_id, user), 10)
        return next((m["content"] for m in reversed(hist) if m["role"] == "user"), "")

    def files_kb(self, lang):
        return kb([
            [("📝 TXT", "fx:txt"), ("📘 MD", "fx:md"), ("🌐 HTML", "fx:html")],
            [("🧾 JSON", "fx:json"), ("📊 CSV", "fx:csv"), ("💻 " + tr(lang, "ملفات الكود", "Code files"), "fx:code")],
            [("📦 " + tr(lang, "مشروع ZIP", "Project ZIP"), "fx:zip")],
            [("🏠 " + tr(lang, "القائمة", "Menu"), "m:main")],
        ])

    def show_files(self, chat_id, user, mid=None) -> None:
        lang = user["lang"]
        last = self._last_answer(chat_id, user)
        n = len(F.extract_files(last)) if last else 0
        text = (f"📁 <b>{tr(lang, 'تصدير الإجابة الأخيرة', 'Export the last answer')}</b>\n"
                f"<blockquote>💻 {n} {tr(lang, 'ملف كود مكتشف', 'code file(s) detected')}\n"
                f"📦 ZIP = {tr(lang, 'كل الملفات + نص الإجابة', 'all files + the answer text')}\n"
                f"✏️ /save name.ext {tr(lang, 'نص…', 'text…')} — {tr(lang, 'أنشئ ملفك الخاص', 'create your own file')}</blockquote>")
        self._html_screen(chat_id, mid, text, self.files_kb(lang))

    def cmd_files(self, chat_id, user, args) -> None:
        self.show_files(chat_id, user)

    def cmd_zip(self, chat_id, user, args) -> None:
        self.export_last(chat_id, user, "zip")

    def export_last(self, chat_id, user, fmt: str) -> None:
        lang = user["lang"]
        if not self.limiter.allow(user["id"]):                      # exports are uploads: keep them inside the rate limit
            self.tg.send_message(chat_id, tr(lang, "⏳ مهلاً، حاول بعد قليل.", "⏳ Slow down, try again shortly."))
            return
        last = self._last_answer(chat_id, user)
        if not last:
            self.tg.send_message(chat_id, tr(lang, "لا توجد إجابة لتصديرها.", "There is no answer to export."))
            return
        stamp = time.strftime("%Y%m%d-%H%M")
        code = F.extract_files(last)
        if fmt == "txt":
            self.tg.send_document(chat_id, f"darwin-{stamp}.txt", F.to_plain(last).encode("utf-8"))
        elif fmt == "md":
            self.tg.send_document(chat_id, f"darwin-{stamp}.md", last.encode("utf-8"))
        elif fmt == "html":
            self.tg.send_document(chat_id, f"darwin-{stamp}.html", F.to_html_page(last, to_html(last)))
        elif fmt == "json":
            self.tg.send_document(chat_id, f"darwin-{stamp}.json", F.to_json(self._last_question(chat_id, user), last, code))
        elif fmt == "csv":
            data = F.first_table_csv(last)
            if data is None:
                self.tg.send_message(chat_id, tr(lang, "📊 لا يوجد جدول في الإجابة الأخيرة.", "📊 The last answer has no table."))
                return
            self.tg.send_document(chat_id, f"darwin-table-{stamp}.csv", data)
        elif fmt == "code":
            if not code:
                self.tg.send_message(chat_id, tr(lang, "💻 لا توجد كتل كود في الإجابة الأخيرة.", "💻 No code blocks in the last answer."))
                return
            for name, content in code[:MAX_CODE_SENDS]:
                self.tg.send_document(chat_id, name.replace("/", "_"), content.encode("utf-8"))
            if len(code) > MAX_CODE_SENDS:
                self.tg.send_message(chat_id, tr(lang, f"📦 أرسلت {MAX_CODE_SENDS} من {len(code)}؛ استخدم ZIP للبقية.",
                                                 f"📦 Sent {MAX_CODE_SENDS} of {len(code)}; use ZIP for the rest."))
        elif fmt == "zip":
            try:
                data = F.make_zip(code, last)
            except ValueError:
                self.tg.send_message(chat_id, tr(lang, "📦 المشروع كبير جداً للتصدير.", "📦 The project is too large to export."))
                return
            self.tg.send_document(chat_id, f"darwin-project-{stamp}.zip", data,
                                  caption=tr(lang, f"📦 {len(code)} ملف + ANSWER.md", f"📦 {len(code)} file(s) + ANSWER.md"))

    def cmd_save(self, chat_id, user, args) -> None:
        """/save name.ext [text]  — make any file; with no text it saves the first code block of the last answer."""
        lang = user["lang"]
        parts = args.strip().split(None, 1)
        name, body = (parts + ["", ""])[:2]
        if not name:
            self.tg.send_message(chat_id, tr(lang, "✏️ الاستخدام: /save app.py ثم النص (أو بدون نص لحفظ أول كود من الإجابة الأخيرة)",
                                             "✏️ Usage: /save app.py then the text (or no text to save the first code block of the last answer)"))
            return
        fname = F.safe_name(name, "file.txt")
        if "." not in fname.rsplit("/", 1)[-1] and fname.rsplit("/", 1)[-1] not in ("Dockerfile", "Makefile"):
            fname += ".txt"
        body = body.strip()
        if not body:
            last = self._last_answer(chat_id, user)
            blocks = F.extract_files(last) if last else []
            body = blocks[0][1] if blocks else (last or "")
        if not body:
            self.tg.send_message(chat_id, tr(lang, "لا يوجد نص لحفظه.", "There is no text to save."))
            return
        data = body.encode("utf-8")
        if len(data) > MAX_SAVE_BYTES:
            self.tg.send_message(chat_id, tr(lang, "الملف كبير جداً (الحد 1MB).", "File too large (1MB limit)."))
            return
        self.tg.send_document(chat_id, fname.replace("/", "_"), data)
