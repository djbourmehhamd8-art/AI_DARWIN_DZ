"""Security command handlers (mixin for BotApp). Local tools answer instantly and cost no API credit."""
from __future__ import annotations

import html
import logging
import re
import time

import requests

from . import __version__
from .brand import CORE_PROMPT
from .i18n import t
from .personas import TASK_PROMPTS
from .security import (cvss, decoder, hashing, ioc, jwt_tool, mailheaders, netinfo, password, ports, timestamps,
                       urlcheck)
from .utils import split_text

log = logging.getLogger("bot.sec")

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
# commands whose argument may come from the message being replied to
REPLY_ARG_CMDS = frozenset({"url", "ioc", "hash", "jwt", "headers", "b64", "decode", "cvss", "ip", "defang",
                            "cve", "analyze", "ir", "explain", "harden", "sigma", "port", "ts", "mitre", "hex", "caesar", "entropy",
                            "domain", "dns", "whois", "cert", "webhead", "footprint", "tool", "radar", "flight", "plane", "metar", "weather", "radio",
                            "freq", "wave", "morse", "phonetic", "grid", "power", "fspl", "horizon", "dist", "subdomains", "asn", "rdns",
                            "mac", "exposure"})


class SecurityCommands:
    """Expects: self.tg, self.cfg, self.db, self.ctx (thread-local), self._oneshot()."""

    def security_commands(self) -> dict:
        return {
            "sec": self.cmd_sec, "about": self.cmd_about, "url": self.cmd_url, "ioc": self.cmd_ioc,
            "pass": self.cmd_pass, "genpass": self.cmd_genpass, "hash": self.cmd_hash, "jwt": self.cmd_jwt,
            "headers": self.cmd_headers, "b64": self.cmd_decode, "decode": self.cmd_decode, "cvss": self.cmd_cvss,
            "ip": self.cmd_ip, "defang": self.cmd_defang, "cve": self.cmd_cve, "harden": self.cmd_harden,
            "ir": self.cmd_ir, "explain": self.cmd_explain, "analyze": self.cmd_analyze, "sigma": self.cmd_sigma,
            "port": self.cmd_port, "ts": self.cmd_ts, "mitre": self.cmd_mitre,
        }

    # ------------------------------------------------------------------ helpers
    def send_long(self, chat_id, text: str, reply_markup=None) -> None:
        reply_markup = reply_markup or getattr(self.ctx, "after_kb", None)
        parts = split_text(text, 3900)
        for i, p in enumerate(parts):
            self.tg.send_message(chat_id, p, reply_markup if i == len(parts) - 1 else None)

    def send_html_lines(self, chat_id, lines: list, reply_markup=None) -> None:
        """Send HTML lines (each one self-contained) in as few messages as possible; falls back to plain text."""
        reply_markup = reply_markup or getattr(self.ctx, "after_kb", None)
        chunks, cur, size = [], [], 0
        for ln in lines:
            if cur and size + len(ln) > 3500:
                chunks.append(cur)
                cur, size = [], 0
            cur.append(ln)
            size += len(ln) + 1
        if cur:
            chunks.append(cur)
        for i, c in enumerate(chunks):
            h = "\n".join(c)
            plain = html.unescape(re.sub(r"<[^>]+>", "", h))
            self.tg.send_rich(chat_id, h, plain, reply_markup if i == len(chunks) - 1 else None)

    def _hibp_fetch(self, prefix: str) -> str:
        sess = getattr(self, "_hibp", None)
        if sess is None:
            sess = self._hibp = requests.Session()
        r = sess.get(f"https://api.pwnedpasswords.com/range/{prefix}", headers={"Add-Padding": "true"}, timeout=6)
        r.raise_for_status()
        return r.text

    def _sec_gate(self, chat_id, user) -> bool:
        """Rate-limit local tools too, so the bot cannot be used as a CPU/network amplifier."""
        if not self.limiter.allow(user["id"]):
            self.tg.send_message(chat_id, t(user["lang"], "rate"))
            return False
        return True

    def _need(self, chat_id, user, args, key) -> bool:
        if not args.strip():
            self.tg.send_message(chat_id, t(user["lang"], key))
            return False
        return True

    # ------------------------------------------------------------------ menu / about
    def cmd_sec(self, chat_id, user, args):
        self.show_tools(chat_id, user)

    def cmd_about(self, chat_id, user, args):
        self.tg.send_message(chat_id, t(user["lang"], "about", ver=__version__))

    # ------------------------------------------------------------------ local tools
    def cmd_url(self, chat_id, user, args):
        if not self._need(chat_id, user, args, "sec_usage_url") or not self._sec_gate(chat_id, user):
            return
        lang = user["lang"]
        urls = ioc.extract(args)["urls"] or [args.split()[0]]
        out = [urlcheck.describe(urlcheck.analyze(u), lang) for u in urls[:5]]
        self.send_long(chat_id, "\n\n".join(out))

    def cmd_ioc(self, chat_id, user, args):
        if not self._need(chat_id, user, args, "sec_usage_ioc") or not self._sec_gate(chat_id, user):
            return
        lang = user["lang"]
        found = ioc.extract(args)
        names = {"urls": "URLs", "ips": "IPs", "domains": "Domains", "emails": "Emails",
                 "sha256": "SHA-256", "sha1": "SHA-1", "md5": "MD5", "cves": "CVEs"}
        lines = []
        for key, label in names.items():
            vals = found[key]
            if not vals:
                continue
            lines.append(f"\n▪️ <b>{label}</b> ({len(vals)})")
            for v in vals[:25]:
                shown = v if key in ("sha256", "sha1", "md5", "cves") else ioc.defang(v)
                extra = " <i>(private)</i>" if key == "ips" and ioc.is_private_ip(v) else ""
                lines.append(f"<code>{html.escape(shown, quote=False)}</code>{extra}")
        if not lines:
            self.send_long(chat_id, t(lang, "sec_no_ioc"))
            return
        self.send_html_lines(chat_id, [html.escape(t(lang, "sec_ioc_head"), quote=False)] + lines)

    def cmd_pass(self, chat_id, user, args):
        lang = user["lang"]
        if not self._need(chat_id, user, args, "sec_usage_pass") or not self._sec_gate(chat_id, user):
            return
        pw = args.strip()
        mid = getattr(self.ctx, "msg_id", None)
        if mid:
            self.tg.delete_message(chat_id, mid)          # do not leave the password in the chat history
        res = password.analyze(pw)
        pwned = password.pwned_count(pw, self._hibp_fetch) if self.cfg.hibp else None
        if pwned == -1:
            pwned = None
        self.send_long(chat_id, password.describe(res, lang, pwned))

    def cmd_genpass(self, chat_id, user, args):
        if not self._sec_gate(chat_id, user):
            return
        n = int(args) if args.strip().isdigit() else 20
        n = max(8, min(n, 64))
        pw = password.generate(n)
        text = t(user["lang"], "sec_genpass_out", n=n, p="\x00")
        h = html.escape(text, quote=False).replace("\x00", f"<code>{html.escape(pw, quote=False)}</code>")
        sent = self.tg.send_rich(chat_id, h, text.replace("\x00", pw), getattr(self.ctx, "after_kb", None))
        if sent and sent.get("message_id"):
            self.schedule_delete(chat_id, sent["message_id"], 60)       # do not leave a password in the chat

    def cmd_hash(self, chat_id, user, args):
        lang = user["lang"]
        if not self._need(chat_id, user, args, "sec_usage_hash") or not self._sec_gate(chat_id, user):
            return
        text = args.strip()
        cands = hashing.identify(text) if " " not in text else []
        if cands:
            lines = [t(lang, "sec_hash_ident", c=" / ".join(cands))]
            if any(c in hashing.WEAK for c in cands):
                lines.append(t(lang, "sec_hash_weak"))
            self.send_long(chat_id, "\n".join(lines))
            return
        lines = [f"<b>{html.escape(k, quote=False)}</b>\n<code>{html.escape(v, quote=False)}</code>"
                 for k, v in hashing.digests(text).items()]
        self.send_html_lines(chat_id, lines)

    def cmd_jwt(self, chat_id, user, args):
        lang = user["lang"]
        if not self._need(chat_id, user, args, "sec_usage_jwt") or not self._sec_gate(chat_id, user):
            return
        res = jwt_tool.inspect(args.strip())
        self.send_long(chat_id, jwt_tool.describe(res, lang) if res.get("ok") else t(lang, "sec_jwt_bad"))

    def cmd_headers(self, chat_id, user, args):
        lang = user["lang"]
        if not self._need(chat_id, user, args, "sec_usage_headers") or not self._sec_gate(chat_id, user):
            return
        res = mailheaders.analyze(args)
        self.send_long(chat_id, mailheaders.describe(res, lang) if res.get("ok") else t(lang, "sec_headers_bad"))

    def cmd_decode(self, chat_id, user, args):
        """Peel layers of Base64 / Hex / URL encoding; plain text is Base64-encoded instead."""
        lang = user["lang"]
        if not self._need(chat_id, user, args, "sec_usage_decode") or not self._sec_gate(chat_id, user):
            return
        s = args.strip()
        chain = decoder.decode_chain(s)
        if chain:
            lines = [f"<b>{html.escape(t(lang, 'sec_decode_head'), quote=False)}</b>"]
            for i, (method, text) in enumerate(chain, 1):
                body = html.escape(ioc.defang_text(text)[:1500], quote=False)
                lines.append(f"{i}. <i>{html.escape(method, quote=False)}</i>\n<pre>{body}</pre>")
            lines.append(html.escape(t(lang, "sec_decode_note"), quote=False))
            self.send_html_lines(chat_id, lines)
        else:
            self.send_long(chat_id, t(lang, "sec_b64_enc", x=hashing.b64_encode(s)[:3500]))

    def cmd_cvss(self, chat_id, user, args):
        lang = user["lang"]
        if not self._need(chat_id, user, args, "sec_usage_cvss") or not self._sec_gate(chat_id, user):
            return
        res = cvss.calculate(args.strip().split()[0])
        self.send_long(chat_id, cvss.describe(res, lang) if res["ok"] else t(lang, "sec_cvss_bad"))

    def cmd_ip(self, chat_id, user, args):
        lang = user["lang"]
        if not self._need(chat_id, user, args, "sec_usage_ip") or not self._sec_gate(chat_id, user):
            return
        res = netinfo.analyze(args)
        self.send_long(chat_id, netinfo.describe(res, lang) if res["ok"] else t(lang, "sec_ip_bad"))

    def cmd_defang(self, chat_id, user, args):
        if not self._need(chat_id, user, args, "sec_usage_defang") or not self._sec_gate(chat_id, user):
            return
        body = ioc.defang_text(args.strip())[:3300]
        self.send_html_lines(chat_id, [f"<pre>{html.escape(body, quote=False)}</pre>"])

    # ------------------------------------------------------------------ AI-assisted workflows
    def _task(self, chat_id, user, task: str, args: str, usage_key: str) -> None:
        if not self._need(chat_id, user, args, usage_key):
            return
        self._oneshot(chat_id, user, CORE_PROMPT, TASK_PROMPTS[task].format(x=args.strip()[:6000]),
                      temperature=0.3, remember=True)

    def cmd_cve(self, chat_id, user, args):
        if not self._need(chat_id, user, args, "sec_usage_cve"):
            return
        cve = args.strip().split()[0].upper()
        if not CVE_RE.match(cve):
            self.tg.send_message(chat_id, t(user["lang"], "sec_bad_cve"))
            return
        self._task(chat_id, user, "cve", cve, "sec_usage_cve")

    def cmd_mitre(self, chat_id, user, args):
        self._task(chat_id, user, "mitre", args, "sec_usage_mitre")

    def cmd_port(self, chat_id, user, args):
        lang = user["lang"]
        if not self._need(chat_id, user, args, "sec_usage_port"):
            return
        items = ports.lookup(args)
        if not items:
            self.tg.send_message(chat_id, t(lang, "sec_port_none"))
            return
        head = f"🔌 <b>{html.escape(t(lang, 'sec_port_head'), quote=False)}</b>"
        self.send_html_lines(chat_id, [head, ""] + ports.describe(items, lang) + ["", "🟢 low · 🟡 medium · 🔴 high"])

    def cmd_ts(self, chat_id, user, args):
        lang = user["lang"]
        if not self._need(chat_id, user, args, "sec_usage_ts"):
            return
        q = args.strip()
        if q.lower() == "now":
            q = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        res = timestamps.analyze(q)
        if not res["ok"]:
            self.tg.send_message(chat_id, t(lang, "sec_ts_bad"))
            return
        title = t(lang, "sec_ts_decode" if res["kind"] == "decode" else "sec_ts_encode")
        lines = [f"🕓 <b>{html.escape(title, quote=False)}</b>", ""]
        for label, val in res["items"]:
            lines.append(f"<b>{html.escape(label, quote=False)}</b>\n<code>{html.escape(val, quote=False)}</code>")
        self.send_html_lines(chat_id, lines)

    def cmd_harden(self, chat_id, user, args):
        self._task(chat_id, user, "harden", args, "sec_usage_harden")

    def cmd_ir(self, chat_id, user, args):
        self._task(chat_id, user, "ir", args, "sec_usage_ir")

    def cmd_explain(self, chat_id, user, args):
        self._task(chat_id, user, "explain", args, "sec_usage_explain")

    def cmd_analyze(self, chat_id, user, args):
        self._task(chat_id, user, "analyze", args, "sec_usage_analyze")

    def cmd_sigma(self, chat_id, user, args):
        self._task(chat_id, user, "sigma", args, "sec_usage_sigma")
