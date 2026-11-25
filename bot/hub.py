"""Tools hub: every offline tool grouped by purpose, with search and a per-user "recent tools" shelf.

/hub (or /tools) opens it; /tools csp searches it. The hub only builds screens: the tools themselves are the same
`t:<kind>` buttons and /<kind> commands as before, so nothing else needs to know about categories.
"""
from __future__ import annotations

import html

from .ui import TOOLS, chunk, kb, tr
from .utildata import UTILS

RECENT_MAX = 6

# id, icon, Arabic, English, tool kinds (a tool may appear in several categories)
CATEGORIES = (
    ("web", "🛡", "أمن الويب والتطبيقات", "Web & app security",
     ("csp", "cookie", "secheaders", "webhead", "cert", "url", "jwt", "sri", "useragent", "secrets")),
    ("net", "🌐", "الشبكات والنطاقات", "Network & domains",
     ("domain", "dns", "spf", "dmarc", "whois", "subdomains", "asn", "rdns", "mac", "ip", "port", "subnet", "cidrmatch", "ipconv", "exposure")),
    ("crypto", "🔐", "التشفير والترميز", "Crypto & encoding",
     ("hash", "pass", "genpass", "decode", "hex", "caesar", "entropy", "urlenc", "uuid", "sri")),
    ("dfir", "🕵️", "التحقيق والاستجابة", "Forensics & response",
     ("ioc", "defang", "secrets", "headers", "ts", "date", "cvss", "diff", "footprint", "entropy")),
    ("dev", "🧮", "أدوات عامة ومطوّرين", "Everyday & dev",
     ("calc", "unit", "pct", "json", "regex", "cron", "chmod", "diff", "date", "textstat", "uniq", "color", "caseconv", "slug", "roll")),
)

# kind -> (icon, Arabic, English)
LABELS: dict = {k: (ic, ar, en) for k, ic, ar, en in TOOLS}
LABELS.update({k: (ic, ar, en) for k, ic, ar, en, *_ in UTILS})
LABELS["genpass"] = ("🎲", "مولّد كلمة مرور", "Password generator")

CAT_BY_ID = {c[0]: c for c in CATEGORIES}
HUB_KINDS = frozenset(k for c in CATEGORIES for k in c[4])
SEARCH_KEYWORDS = {                      # extra words people type that are not in the labels
    "csp": "content security policy xss", "cookie": "set-cookie session samesite httponly", "secheaders": "hsts headers grade",
    "spf": "email spoofing mail", "dmarc": "email spoofing mail", "secrets": "leak api key token credentials password scan",
    "sri": "integrity subresource script cdn", "chmod": "permissions linux umask", "cidrmatch": "firewall acl allowlist range",
    "ipconv": "ip decimal hex binary ipv6", "useragent": "ua browser bot", "diff": "compare changes", "date": "days between deadline time",
    "subnet": "cidr netmask network", "cron": "schedule crontab", "hash": "md5 sha1 sha256", "pass": "password strength",
    "decode": "base64 deobfuscate", "ioc": "indicators extract ip domain", "jwt": "token json web", "cvss": "severity score",
}


def _e(x) -> str:
    return html.escape(str(x), quote=False)


def label(kind: str, lang: str) -> str:
    ic, ar, en = LABELS.get(kind, ("🔧", kind, kind))
    return f"{ic} {ar if lang == 'ar' else en}"


def search_kinds(query: str, limit: int = 12) -> list:
    """Kinds whose name, label, category or keywords contain every word of the query (best matches first)."""
    words = [w for w in query.casefold().replace("/", " ").split() if w]
    if not words:
        return []
    scored = []
    for kind in sorted(HUB_KINDS):
        _ic, ar, en = LABELS.get(kind, ("", kind, kind))
        cats = " ".join(f"{c[2]} {c[3]}" for c in CATEGORIES if kind in c[4])
        hay = f"{kind} {ar} {en} {SEARCH_KEYWORDS.get(kind, '')} {cats}".casefold()
        if all(w in hay for w in words):
            exact = 0 if kind == words[0] else 1 if kind.startswith(words[0]) else 2 if any(words[0] in x.casefold() for x in (ar, en)) else 3
            scored.append((exact, kind))
    scored.sort()
    return [k for _, k in scored[:limit]]


class HubMixin:
    def hub_commands(self) -> dict:
        return {"hub": self.cmd_hub, "tools": self.cmd_hub}

    # ------------------------------------------------------------------ recent tools
    def recent_tools(self, uid: int) -> list:
        raw = self.db.get_setting(f"recent:{uid}", "")
        return [k for k in raw.split(",") if k in HUB_KINDS][:RECENT_MAX]

    def note_tool(self, uid: int, kind: str) -> None:
        """Move `kind` to the front of the user's recent list (one tiny write, skipped when nothing changes)."""
        if kind not in HUB_KINDS:
            return
        cur = self.recent_tools(uid)
        new = [kind] + [k for k in cur if k != kind]
        new = new[:RECENT_MAX]
        if new != cur:
            self.db.set_setting(f"recent:{uid}", ",".join(new))

    # ------------------------------------------------------------------ screens
    def hub_kb(self, lang, uid):
        rows = chunk([(f"{ic} {ar if lang == 'ar' else en} ({len(kinds)})", f"h:c:{cid}") for cid, ic, ar, en, kinds in CATEGORIES], 2)
        recent = self.recent_tools(uid)
        rows.append(([("⭐ " + tr(lang, f"الأخيرة ({len(recent)})", f"Recent ({len(recent)})"), "h:r")] if recent else [])
                    + [("🔎 " + tr(lang, "بحث عن أداة", "Find a tool"), "t:hubq")])
        rows.append([("📋 " + tr(lang, "كل أدوات الأمن", "All security tools"), "m:tools"), ("🧮 " + tr(lang, "الأدوات الإضافية", "Extra tools"), "m:utils")])
        rows.append([("📚 " + tr(lang, "دليل الأدوات", "Tools guide"), "m:toolkit"), ("🌐 " + tr(lang, "دردشة AI (ويب)", "AI chat (web)"), "m:wc")])
        rows.append(self.home_row(lang))
        return kb(rows)

    def show_hub(self, chat_id, user, mid=None) -> None:
        lang = user["lang"]
        text = tr(lang, f"🧰 <b>مركز الأدوات</b> — {len(HUB_KINDS)} أداة تعمل دون إنترنت ولا تستهلك رصيد الذكاء الاصطناعي.\nاختر فئة، أو اكتب <code>/tools كلمة</code> للبحث.",
                  f"🧰 <b>Tools hub</b> — {len(HUB_KINDS)} offline tools, no AI credit used.\nPick a category, or type <code>/tools word</code> to search.")
        markup = self.hub_kb(lang, user["id"])
        if mid and self.tg.edit_rich(chat_id, mid, text, text, markup):
            return
        self.tg.send_rich(chat_id, text, text, markup)

    def _tool_buttons(self, lang, kinds) -> list:
        return chunk([(label(k, lang), f"t:{k}") for k in kinds], 2)

    def _hub_screen(self, chat_id, mid, text, rows, lang) -> None:
        markup = kb(rows + [[("🔙 " + tr(lang, "المركز", "Hub"), "h:home")] + self.home_row(lang)])
        if mid and self.tg.edit_rich(chat_id, mid, text, text, markup):
            return
        self.tg.send_rich(chat_id, text, text, markup)

    def show_category(self, chat_id, user, cid: str, mid=None) -> None:
        lang = user["lang"]
        cat = CAT_BY_ID.get(cid)
        if not cat:
            return self.show_hub(chat_id, user, mid)
        _, ic, ar, en, kinds = cat
        self._hub_screen(chat_id, mid, f"{ic} <b>{_e(ar if lang == 'ar' else en)}</b> — {len(kinds)} " + tr(lang, "أداة", "tools"),
                         self._tool_buttons(lang, kinds), lang)

    def show_recent(self, chat_id, user, mid=None) -> None:
        lang = user["lang"]
        recent = self.recent_tools(user["id"])
        if not recent:
            return self.show_hub(chat_id, user, mid)
        self._hub_screen(chat_id, mid, "⭐ <b>" + tr(lang, "أدواتك الأخيرة", "Your recent tools") + "</b>", self._tool_buttons(lang, recent), lang)

    def show_search(self, chat_id, user, query: str, mid=None) -> None:
        lang = user["lang"]
        found = search_kinds(query)
        if not found:
            text = tr(lang, f"🔎 لا أداة تطابق «{_e(query[:40])}». جرّب كلمة أخرى مثل: <code>dns</code> · <code>hash</code> · <code>cookie</code> · <code>cron</code>",
                      f"🔎 No tool matches “{_e(query[:40])}”. Try another word such as: <code>dns</code> · <code>hash</code> · <code>cookie</code> · <code>cron</code>")
            return self._hub_screen(chat_id, mid, text, [[("🔎 " + tr(lang, "بحث جديد", "New search"), "t:hubq")]], lang)
        self._hub_screen(chat_id, mid, f"🔎 <b>{_e(query[:40])}</b> — {len(found)}", self._tool_buttons(lang, found), lang)

    def cmd_hub(self, chat_id, user, args) -> None:
        if not self._sec_gate(chat_id, user):
            return
        q = (args or "").strip()[:60]
        self.show_search(chat_id, user, q) if q else self.show_hub(chat_id, user)

    # ------------------------------------------------------------------ callbacks
    def hub_callback(self, action, v, w, chat_id, user, mid) -> bool:
        if action != "h":
            return False
        if v == "c":
            self.show_category(chat_id, user, w, mid)
        elif v == "r":
            self.show_recent(chat_id, user, mid)
        else:
            self.show_hub(chat_id, user, mid)
        return True
