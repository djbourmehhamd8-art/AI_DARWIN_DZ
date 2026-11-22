"""Advanced defensive tools (domain intel, DNS, domain age, TLS, site headers, handle footprint, tool catalogue),
answer verification, CVE grounding and natural-conversation handling."""
from __future__ import annotations

import html
import re
import time
from concurrent.futures import ThreadPoolExecutor

from . import chatstyle, cvedata, netintel, toolkit
from .brand import CORE_PROMPT
from .render import Typing
from .ui import kb, tr

DOT = {"high": "🔴", "medium": "🟠", "low": "🟡", "info": "🔵", "ok": "🟢"}
FINDING = {
    "no_spf": ("لا يوجد سجل SPF: يسهل انتحال بريد النطاق", "No SPF record: the domain's email is easy to spoof"),
    "spf_open": ("SPF يسمح لأي مرسل (+all)", "SPF allows any sender (+all)"),
    "spf_neutral": ("SPF بسياسة محايدة (?all)", "SPF has a neutral policy (?all)"),
    "spf_soft": ("SPF بفشل ناعم (~all): الأفضل -all بعد التأكد", "SPF soft-fail (~all): prefer -all once verified"),
    "no_dmarc": ("لا يوجد DMARC: لا حماية ضد انتحال النطاق", "No DMARC: no protection against domain spoofing"),
    "dmarc_none": ("DMARC بسياسة none (مراقبة فقط)", "DMARC policy is none (monitoring only)"),
    "no_caa": ("لا يوجد CAA لتقييد جهات إصدار الشهادات", "No CAA record restricting certificate issuers"),
    "no_records": ("لا توجد سجلات DNS لهذا الاسم", "No DNS records for this name"),
    "very_new": ("النطاق عمره أقل من 30 يوماً — مؤشر تصيّد قوي", "Domain is under 30 days old — a strong phishing indicator"),
    "new": ("نطاق حديث (أقل من 6 أشهر)", "Recently registered domain (under 6 months)"),
    "expiring": ("ينتهي قريباً (أقل من 30 يوماً)", "Expires soon (under 30 days)"),
    "expired": ("الشهادة منتهية!", "The certificate has EXPIRED"),
    "expiring_soon": ("الشهادة تنتهي خلال أقل من 14 يوماً", "Certificate expires in under 14 days"),
    "old_tls": ("بروتوكول TLS قديم", "Outdated TLS protocol"),
    "wildcard": ("شهادة wildcard (تغطي كل النطاقات الفرعية)", "Wildcard certificate (covers all subdomains)"),
}
CHECK_NAMES = {"hsts": "HSTS", "csp": "Content-Security-Policy", "frame": "Clickjacking (X-Frame-Options / frame-ancestors)",
               "nosniff": "X-Content-Type-Options", "referrer": "Referrer-Policy", "permissions": "Permissions-Policy"}
VERIFY_SYSTEM = (CORE_PROMPT + "\n\nROLE: meticulous technical reviewer. You will receive an ANSWER written earlier. Check it for: factual errors, "
                 "outdated information, invented identifiers (CVE ids, versions, commands, flags, URLs), insecure or destructive advice, and "
                 "missing caveats. Output in the user's language: 1) verdict line (✅ Accurate / ⚠️ Mostly accurate / ❌ Needs correction), "
                 "2) a short list of issues with severity (🔴🟠🟡) and why, 3) corrected text ONLY for the wrong parts. Never invent: say "
                 "\"cannot verify\" when unsure, and point to the official source to check.")
TOOL_PROMPT = ("Recommend the best tools for the need below. Prefer tools from this catalogue; you may add other well-known tools but label them "
               "'(outside catalogue)'. For each tool: why it fits, when NOT to use it, and a one-line first step. Defensive use first; "
               "for offensive tools add a short authorised-use reminder. End with the single best starting point.\n\nCATALOGUE\n{cat}\n\nNEED\n{x}")


def _e(x) -> str:
    return html.escape(str(x if x is not None else ""), quote=False)


def _plain(h: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", h))


def _date(ts) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(ts)) if ts else "-"


class AdvToolsMixin:
    def adv_commands(self) -> dict:
        return {"domain": self.cmd_domain, "dns": self.cmd_dns, "whois": self.cmd_whois, "cert": self.cmd_cert,
                "webhead": self.cmd_webhead, "footprint": self.cmd_footprint, "toolkit": self.cmd_toolkit,
                "tool": self.cmd_tool, "verify": self.cmd_verify, "smart": self.cmd_smart}

    # ------------------------------------------------------------------ shared helpers
    def _net_gate(self, chat_id, user, args: str, ar: str, en: str) -> bool:
        if not args.strip():
            self.tg.send_message(chat_id, tr(user["lang"], ar, en))
            return False
        return self._sec_gate(chat_id, user)

    def _finding_lines(self, findings: list, lang: str) -> list:
        return [f"{DOT.get(sev, '•')} {_e(tr(lang, *FINDING[key]))}" for sev, key in findings if key in FINDING]

    def _send(self, chat_id, lines: list, markup=None) -> None:
        self.send_html_lines(chat_id, lines, markup)

    def _bad_domain(self, chat_id, user) -> None:
        self.tg.send_message(chat_id, tr(user["lang"], "⚠️ أدخل نطاقاً صحيحاً مثل example.com (لا عناوين IP ولا نطاقات داخلية).",
                                         "⚠️ Enter a valid domain such as example.com (no IP addresses or internal names)."))

    # ------------------------------------------------------------------ DNS
    def _dns_lines(self, domain: str, rep: dict, lang: str) -> list:
        rec = rep["records"]

        def fmt(vals, n=4):
            vals = [v for v in vals if v]
            return "\n".join(_e(v[:110]) for v in vals[:n]) + (f"\n… +{len(vals) - n}" if len(vals) > n else "") if vals else "—"
        body = [f"<b>A</b>\n{fmt(rec['A'])}", f"<b>AAAA</b>\n{fmt(rec['AAAA'], 3)}", f"<b>MX</b>\n{fmt(rec['MX'])}",
                f"<b>NS</b>\n{fmt(rec['NS'])}", f"<b>CAA</b>\n{fmt(rec['CAA'], 3)}"]
        spf = (rep["spf"][0][:110] if rep["spf"] else "—")
        dmarc = (rep["dmarc"][0][:110] if rep["dmarc"] else "—")
        lines = [f"🧬 <b>DNS — {_e(domain)}</b>", "<blockquote expandable>" + "\n\n".join(body) + "</blockquote>",
                 f"✉️ <b>{tr(lang, 'حماية البريد', 'Email authentication')}</b>\n<blockquote>SPF: {'✅' if rep['spf'] else '❌'} <code>{_e(spf)}</code>\n"
                 f"DMARC: {'✅' if rep['dmarc'] else '❌'} <code>{_e(dmarc)}</code></blockquote>"]
        return lines + self._finding_lines(rep["findings"], lang)

    def cmd_dns(self, chat_id, user, args):
        if not self._net_gate(chat_id, user, args, "🧬 /dns نطاق — سجلات DNS وحماية البريد (SPF/DMARC/CAA).", "🧬 /dns domain — DNS records and email authentication."):
            return
        domain = netintel.valid_domain(args)
        if not domain:
            return self._bad_domain(chat_id, user)
        with Typing(self.tg, chat_id):
            rep = netintel.dns_report(domain)
        self.db.add_audit(user["id"], "net_dns", domain)
        self._send(chat_id, self._dns_lines(domain, rep, user["lang"]))

    # ------------------------------------------------------------------ RDAP / WHOIS
    def _whois_lines(self, domain: str, info: dict, lang: str) -> list:
        if not info.get("ok"):
            msg = tr(lang, "غير مسجّل أو لا يوجد RDAP لهذا الامتداد.", "Not registered, or this TLD has no RDAP service.") \
                if info.get("error") == "not_found" else f"({_e(info.get('error'))})"
            return [f"📇 <b>{_e(domain)}</b>\n{msg}"]
        age = info["age_days"]
        age_txt = f"{age} {tr(lang, 'يوم', 'days')}" + (f" ≈ {age // 365}y" if age and age >= 365 else "") if age is not None else "—"
        q = [f"{tr(lang, 'المسجِّل', 'Registrar')}: {_e(info['registrar'] or '—')}",
             f"{tr(lang, 'تاريخ التسجيل', 'Registered')}: {_date(info['created'])}  ({age_txt})",
             f"{tr(lang, 'ينتهي', 'Expires')}: {_date(info['expires'])}" + (f"  ({info['expires_in']} {tr(lang, 'يوم', 'days')})" if info["expires_in"] is not None else ""),
             f"{tr(lang, 'آخر تعديل', 'Last changed')}: {_date(info['changed'])}",
             "NS: " + (_e(", ".join(info["nameservers"])) or "—"),
             f"{tr(lang, 'الحالة', 'Status')}: {_e(', '.join(info['status'][:4]) or '—')}"]
        return [f"📇 <b>RDAP — {_e(domain)}</b>", "<blockquote>" + "\n".join(q) + "</blockquote>"] + self._finding_lines(info["flags"], lang)

    def cmd_whois(self, chat_id, user, args):
        if not self._net_gate(chat_id, user, args, "📇 /whois نطاق — عمر النطاق والمسجِّل (RDAP).", "📇 /whois domain — domain age and registrar (RDAP)."):
            return
        domain = netintel.valid_domain(args)
        if not domain:
            return self._bad_domain(chat_id, user)
        with Typing(self.tg, chat_id):
            try:
                info = netintel.rdap_domain(domain)
            except Exception as e:                                   # noqa: BLE001
                info = {"ok": False, "error": type(e).__name__}
        self.db.add_audit(user["id"], "net_whois", domain)
        self._send(chat_id, self._whois_lines(domain, info, user["lang"]))

    # ------------------------------------------------------------------ TLS
    def _cert_lines(self, domain: str, c: dict, lang: str) -> list:
        if not c.get("ok"):
            why = {"verify_failed": tr(lang, "فشل التحقق من الشهادة", "Certificate verification FAILED"),
                   "connect_failed": tr(lang, "تعذّر الاتصال بالمنفذ 443", "Could not connect to port 443"),
                   "unresolvable_or_private": tr(lang, "الاسم لا يُحلّ أو يشير إلى عنوان غير عام", "Name does not resolve or is not public")}.get(c.get("error"), c.get("error"))
            return [f"🔏 <b>{_e(domain)}</b>\n🔴 {_e(why)}" + (f"\n<code>{_e(c.get('detail'))}</code>" if c.get("detail") else "")]
        q = [f"CN: {_e(c['cn'] or '—')}", f"{tr(lang, 'المُصدِر', 'Issuer')}: {_e(c['issuer'] or '—')}",
             f"{tr(lang, 'صالحة', 'Valid')}: {_date(c['not_before'])} → {_date(c['not_after'])}  (<b>{c['days_left']}</b> {tr(lang, 'يوم متبقٍ', 'days left')})",
             f"TLS: {_e(c['protocol'])} · {_e(c['cipher'])}", f"SAN ({c['san_count']}): {_e(', '.join(c['san'][:6]))}" + (" …" if c["san_count"] > 6 else "")]
        return [f"🔏 <b>TLS — {_e(domain)}</b>", "<blockquote>" + "\n".join(q) + "</blockquote>"] + self._finding_lines(c["flags"], lang)

    def cmd_cert(self, chat_id, user, args):
        if not self._net_gate(chat_id, user, args, "🔏 /cert نطاق — شهادة TLS وصلاحيتها.", "🔏 /cert domain — TLS certificate and expiry."):
            return
        domain = netintel.valid_domain(args)
        if not domain:
            return self._bad_domain(chat_id, user)
        with Typing(self.tg, chat_id):
            c = netintel.tls_info(domain)
        self.db.add_audit(user["id"], "net_cert", domain)
        self._send(chat_id, self._cert_lines(domain, c, user["lang"]))

    # ------------------------------------------------------------------ HTTP security headers
    def _head_lines(self, h: dict, lang: str) -> list:
        if not h.get("ok"):
            return ["🛡 " + tr(lang, "تعذّر الوصول للموقع أو أنه غير عام.", "The site is unreachable or not public.")]
        rows = [f"{'✅' if ok else '❌'} {CHECK_NAMES[k]}" for k, ok, _ in h["checks"]]
        out = [f"🛡 <b>{tr(lang, 'رؤوس أمان الموقع', 'Site security headers')} — {_e(h['url'][:80])}</b>",
               f"<blockquote>{tr(lang, 'الدرجة', 'Grade')}: <b>{h['grade']}</b> · HTTP {h['status']}\n" + "\n".join(rows) + "</blockquote>"]
        if h["leaks"]:
            out.append("🟠 " + tr(lang, "يكشف معلومات الخادم: ", "Leaks server info: ") + _e("; ".join(h["leaks"])))
        if h["cookies"]:
            out.append("🟠 " + tr(lang, "كوكيز ضعيفة: ", "Weak cookies: ") + _e("; ".join(h["cookies"][:3])))
        return out

    def cmd_webhead(self, chat_id, user, args):
        if not self._net_gate(chat_id, user, args, "🛡 /webhead رابط — تقييم رؤوس الأمان (HSTS, CSP…).", "🛡 /webhead url — security headers grade (HSTS, CSP…)."):
            return
        domain = netintel.valid_domain(args)
        if not domain:
            return self._bad_domain(chat_id, user)
        with Typing(self.tg, chat_id):
            h = netintel.sec_headers(args.strip() if "://" in args else domain)
        self.db.add_audit(user["id"], "net_webhead", domain)
        self._send(chat_id, self._head_lines(h, user["lang"]))

    # ------------------------------------------------------------------ everything about a domain in one report
    def cmd_domain(self, chat_id, user, args):
        lang = user["lang"]
        if not self._net_gate(chat_id, user, args, "🌐 /domain نطاق — تقرير شامل: DNS + العمر + TLS + رؤوس الأمان.", "🌐 /domain domain — full report: DNS + age + TLS + headers."):
            return
        domain = netintel.valid_domain(args)
        if not domain:
            return self._bad_domain(chat_id, user)
        with Typing(self.tg, chat_id):
            def safe(fn):
                try:
                    return fn()
                except Exception as e:                               # noqa: BLE001
                    return {"ok": False, "error": type(e).__name__}
            with ThreadPoolExecutor(max_workers=4) as ex:
                f_dns = ex.submit(safe, lambda: netintel.dns_report(domain))
                f_rd = ex.submit(safe, lambda: netintel.rdap_domain(domain))
                f_tls = ex.submit(safe, lambda: netintel.tls_info(domain))
                f_hd = ex.submit(safe, lambda: netintel.sec_headers(domain))
                dns, rd, tls, hd = f_dns.result(), f_rd.result(), f_tls.result(), f_hd.result()
        self.db.add_audit(user["id"], "net_domain", domain)
        sev = [s for s, _ in (dns.get("findings", []) + rd.get("flags", []) + tls.get("flags", []))]
        score = sev.count("high") * 3 + sev.count("medium") * 2 + sev.count("low")
        verdict = ("🔴 " + tr(lang, "مخاطر عالية", "High risk")) if score >= 6 else ("🟠 " + tr(lang, "يحتاج تحسيناً", "Needs attention")) if score >= 3 else \
                  ("🟢 " + tr(lang, "وضع جيد", "Looks good"))
        lines = [f"🌐 <b>{tr(lang, 'تقرير النطاق', 'Domain report')} — {_e(domain)}</b>\n<blockquote>{verdict}"
                 + (f" · {tr(lang, 'الدرجة', 'headers')} <b>{hd['grade']}</b>" if hd.get("ok") else "") + "</blockquote>"]
        if "records" in dns:
            lines += self._dns_lines(domain, dns, lang)
        lines += self._whois_lines(domain, rd, lang) if rd.get("ok") else [f"📇 {tr(lang, 'RDAP غير متاح', 'RDAP unavailable')}"]
        lines += self._cert_lines(domain, tls, lang)
        lines += self._head_lines(hd, lang)
        lines.append("<i>" + tr(lang, "فحص سلبي: استعلام DNS وطلب HTTP/TLS واحد، دون مسح منافذ أو استغلال.", "Passive check: DNS lookups plus one HTTP/TLS request; no port scanning or exploitation.") + "</i>")
        self._send(chat_id, lines)

    # ------------------------------------------------------------------ public handle footprint
    def osint_enabled(self) -> bool:
        v = self.db.get_setting("osint", "")
        return (v != "0") if v else self.cfg.osint

    def cmd_footprint(self, chat_id, user, args):
        lang = user["lang"]
        if not self.osint_enabled():
            self.tg.send_message(chat_id, tr(lang, "👣 هذه الأداة معطّلة من المدير.", "👣 This tool is disabled by the admin."))
            return
        if not args.strip():
            self.tg.send_message(chat_id, tr(
                lang, "👣 /footprint معرّف — يفحص أي المنصات العامة تحمل هذا المعرّف (لمعرّفاتك أو بتفويض: انتحال، علامة تجارية، تحقيق مصرّح).",
                "👣 /footprint handle — checks which public platforms use this username (your own handles or authorised work: impersonation, brand, investigations)."))
            return
        name = netintel.valid_username(args)
        if not name:
            self.tg.send_message(chat_id, tr(
                lang, "⚠️ أدخل معرّفاً عاماً فقط (3–32 حرفاً: أحرف وأرقام و . _ -). لا أبحث بأرقام الهاتف أو البريد أو الهويات أو معرّفات تيليجرام الرقمية، ولا أُحدّد هوية أشخاص.",
                "⚠️ Enter a public username only (3–32 chars: letters, digits . _ -). I do not search by phone numbers, emails, ID numbers or numeric Telegram IDs, and I do not identify people."))
            return
        now = time.time()
        hist = [x for x in self._osint_hist.get(user["id"], []) if now - x < 3600]
        cap = 30 if self.is_admin(user["id"]) else 6
        if len(hist) >= cap:
            self.tg.send_message(chat_id, tr(lang, f"⏳ الحد {cap} فحصاً في الساعة. حاول لاحقاً.", f"⏳ Limit is {cap} checks per hour. Try again later."))
            return
        if not self._sec_gate(chat_id, user):
            return
        self._osint_hist[user["id"]] = hist + [now]
        with Typing(self.tg, chat_id):
            res = netintel.footprint(name)
        self.db.add_audit(user["id"], "footprint", name)
        lines = [f"👣 <b>{tr(lang, 'بصمة المعرّف العام', 'Public handle footprint')}</b> — <code>{_e(name)}</code>"]
        if res["found"]:
            lines.append("<blockquote expandable>" + "\n".join(f'✅ <a href="{_e(u)}">{_e(n)}</a>' for n, u in res["found"]) + "</blockquote>")
        else:
            lines.append(tr(lang, "لم يُعثر على المعرّف في المنصات المفحوصة.", "The handle was not found on the checked platforms."))
        lines.append(f"⚪ {tr(lang, 'غير موجود', 'Not found')}: {len(res['missing'])} · ❔ {tr(lang, 'تعذّر الفحص', 'Could not check')}: "
                     f"{_e(', '.join(res['unknown'])) or '0'} · {tr(lang, 'المجموع', 'checked')}: {res['checked']}")
        lines.append("<i>" + tr(lang, "ℹ️ يعرض هذا الفحص وجود معرّف عام فقط؛ تطابق الاسم لا يثبت أنه الشخص نفسه. استخدمه لمعرّفاتك أو بتفويض مشروع، ولا تستخدمه لملاحقة أحد.",
                                   "ℹ️ This only shows that a public handle exists; a matching name does not prove it is the same person. Use it for your own handles or with a legitimate authorisation — never to follow or harass anyone.") + "</i>")
        self._send(chat_id, lines)

    def adm_osint(self, chat_id, user, args):
        a = args.strip().lower()
        if a in ("on", "off"):
            self.db.set_setting("osint", "1" if a == "on" else "0")
            self.db.add_audit(user["id"], "osint", a)
        self.tg.send_message(chat_id, f"👣 /footprint: {'ON' if self.osint_enabled() else 'OFF'}  (/osint on|off)")

    # ------------------------------------------------------------------ tool catalogue
    def show_toolkit(self, chat_id, user, mid=None) -> None:
        lang = user["lang"]
        items = [(f"{ic} {ar if lang == 'ar' else en}", f"tk:{k}") for k, ic, ar, en, n in toolkit.categories()]
        rows = [items[i:i + 2] for i in range(0, len(items), 2)]
        rows.append([("🧭 " + tr(lang, "اقترح لي أداة لحاجتي", "Recommend a tool for my need"), "t:tool", "success")])
        rows.append(self.home_row(lang))
        text = (f"📚 <b>{tr(lang, 'دليل الأدوات والتوزيعات الأمنية', 'Security tools & distributions guide')}</b>\n"
                f"<i>{tr(lang, 'مواقع رسمية فقط. اختر فئة، أو اكتب /tool وصف حاجتك.', 'Official sites only. Pick a category, or type /tool and describe your need.')}</i>")
        self._html_screen(chat_id, mid, text, kb(rows))

    def toolkit_callback(self, key: str, chat_id, user, mid) -> None:
        if key not in toolkit.CATALOG:
            return
        lang = user["lang"]
        self._html_screen(chat_id, mid, toolkit.category_html(key, lang), kb([
            [("🧭 " + tr(lang, "اقترح لي", "Recommend"), "t:tool"), ("🔙 " + tr(lang, "الدليل", "Guide"), "m:toolkit")]]))

    def cmd_toolkit(self, chat_id, user, args):
        self.show_toolkit(chat_id, user)

    def cmd_tool(self, chat_id, user, args):
        lang = user["lang"]
        q = args.strip()
        if not q:
            self.ask(chat_id, user, "tool")
            return
        hits = toolkit.search(q)
        if hits:
            lines = [f"📚 <b>{tr(lang, 'من الدليل', 'From the guide')}</b>"]
            lines.append("<blockquote expandable>" + "\n".join(
                f'<a href="{_e(t[3])}">{_e(t[0])}</a> — {_e(t[1] if lang == "ar" else t[2])}' for _, t in hits) + "</blockquote>")
            self._send(chat_id, lines)
        self._oneshot(chat_id, user, CORE_PROMPT, TOOL_PROMPT.format(cat=toolkit.names_for_prompt(), x=q[:1500]), temperature=0.3, remember=True)

    # ------------------------------------------------------------------ accuracy: second-opinion review of the last answer
    def cmd_verify(self, chat_id, user, args):
        last = self.db.last_assistant(self._hk(chat_id, user))
        if not last:
            self.tg.send_message(chat_id, tr(user["lang"], "لا توجد إجابة لأدققها بعد.", "There is no answer to review yet."))
            return
        self._oneshot(chat_id, user, VERIFY_SYSTEM, "ANSWER TO REVIEW:\n" + last[:6000], temperature=0.1)

    # ------------------------------------------------------------------ CVE grounding
    def cve_facts(self, ids: list) -> list:
        if not ids:
            return []
        with ThreadPoolExecutor(max_workers=len(ids)) as ex:
            return list(ex.map(lambda c: cvedata.fetch(c, api_key=self.cfg.nvd_api_key), ids))

    def cmd_cve(self, chat_id, user, args):
        """Explain a CVE with VERIFIED NVD/EPSS/KEV facts shown as a card and handed to the model as ground truth."""
        if not self._need(chat_id, user, args, "sec_usage_cve"):
            return
        cve = args.strip().split()[0].upper()
        if not cvedata.CVE_ID.fullmatch(cve):
            self.tg.send_message(chat_id, self._t(user, "sec_bad_cve"))
            return
        with Typing(self.tg, chat_id):
            facts = self.cve_facts([cve])[0]
        lang = user["lang"]
        self._send(chat_id, [cvedata.card_html(facts, lang, _e)])
        block = cvedata.prompt_block([facts], time.strftime("%Y-%m-%d")) if facts.get("ok") or facts.get("error") == "not_found" else \
            "NVD data was unavailable right now: label every specific (scores, dates, affected versions) as unverified and tell the user to check NVD."
        self._task(chat_id, user, "cve", cve + "\n\n" + block, "sec_usage_cve")

    def cve_context(self, chat_id, user) -> str:
        """Silent grounding: CVE ids mentioned in the latest message are looked up so the model cannot invent details."""
        if not self.cfg.cve_ground:
            return ""
        hist = self.db.get_history(self._hk(chat_id, user), 4)
        last = next((m["content"] for m in reversed(hist) if m["role"] == "user"), "")
        ids = cvedata.find_ids(last)
        if not ids:
            return ""
        return cvedata.prompt_block(self.cve_facts(ids), time.strftime("%Y-%m-%d"))

    # ------------------------------------------------------------------ natural conversation
    def _t(self, user, key):
        from .i18n import t
        return t(user["lang"], key)

    def smart_enabled(self, uid: int) -> bool:
        return self.db.get_setting(f"smart_off:{uid}", "") != "1"

    def cmd_smart(self, chat_id, user, args):
        lang = user["lang"]
        a = args.strip().lower()
        if a in ("on", "off"):
            self.db.set_setting(f"smart_off:{user['id']}", "0" if a == "on" else "1")
        on = self.smart_enabled(user["id"])
        self.tg.send_message(chat_id, tr(lang, f"🧠 الفهم التلقائي: {'مفعّل' if on else 'متوقف'}\nعند إرسال رابط أو هاش أو CVE أو IP أو نطاق وحده أحلّله مباشرة. /smart on أو /smart off",
                                         f"🧠 Smart detection: {'ON' if on else 'OFF'}\nSend a lone link, hash, CVE, IP or domain and I analyse it right away. /smart on or /smart off"))

    def natural(self, chat_id, user, text: str) -> bool:
        """Greetings/thanks/goodbyes and lone artefacts. Returns True when handled (no AI call needed)."""
        kind = chatstyle.conversation_kind(text)
        if kind:
            name = chatstyle.clean_name(user.get("first_name") or "")
            h = reply_html = chatstyle.reply(kind, user["lang"], _e(name), text)
            markup = kb([[("🏠 " + tr(user["lang"], "القائمة", "Menu"), "m:main"), ("🧰 " + tr(user["lang"], "الأدوات", "Tools"), "m:tools")]]) if kind == "hello" else None
            self.tg.send_rich(chat_id, h, _plain(reply_html), markup)
            return True
        if self.smart_enabled(user["id"]):
            routed = chatstyle.smart_route(text)
            if routed and routed[0] in self.commands:
                self.commands[routed[0]](chat_id, user, routed[1])
                return True
        return False
