"""Strings for the button interface and the newer tools (override older keys of the same name)."""

UI_STRINGS = {
    "ar": {
        "sec_usage_port": "🔌 الاستخدام: /port 3389  أو  /port 22,445  أو  /port 20-25  أو  /port ssh",
        "sec_usage_ts": "🕓 الاستخدام: /ts 1700000000  أو  /ts 2024-05-01T10:00:00Z  أو  /ts now",
        "sec_usage_mitre": "🗺 الاستخدام: /mitre T1059.001  أو  /mitre Kerberoasting",
        "sec_port_none": "لم أجد هذا المنفذ أو الخدمة في قاعدتي المحلية. جرّب رقماً شائعاً مثل 443 أو اسماً مثل rdp.",
        "sec_port_head": "المنافذ والمخاطر",
        "sec_ts_bad": "لم أفهم الطابع الزمني. أرسل رقماً (Unix/FILETIME/WebKit) أو تاريخاً بصيغة ISO أو now.",
        "sec_ts_decode": "التفسيرات المحتملة (UTC)",
        "sec_ts_encode": "تحويل التاريخ",
        "welcome": ("🛡 <b>أهلاً {name}! أنا DARWIN DZ</b>\nنموذج ذكاء اصطناعي متخصص في الأمن السيبراني.\n\n"
                    "💬 اكتب سؤالك مباشرة\n"
                    "📎 أو أرسل سجلاً / كوداً / ملف إعدادات لتحليله\n"
                    "🧰 أو افتح أدوات الأمن السريعة من الأزرار 👇"),
        "help": ("📖 <b>كيف أستخدم البوت؟</b>\n\n"
                 "<b>💬 المحادثة</b>\n"
                 "• اكتب أي سؤال أمني وسأجيب مباشرة.\n"
                 "• تحت كل إجابة أزرار: إعادة · أكمل · اختصر · ترجم.\n"
                 "• ⏹ تظهر أثناء الكتابة لإيقاف الرد.\n\n"
                 "<b>🧰 أدوات الأمن</b> — محلية وسريعة بلا رصيد\n"
                 "• اضغط الأداة ثم أرسل المدخل (رابط، نص، هاش، توكن...).\n\n"
                 "<b>🤖 مساعد الأمن</b>\n"
                 "• CVE، تحصين، استجابة لحادثة، تحليل سجل، قواعد كشف.\n"
                 "• أرسل ملفاً مع تعليق ليُحلَّل، أو ردّ على رسالة لتمرير نصها للأداة.\n\n"
                 "<b>🗂 التنظيم</b>\n"
                 "• القضايا: مساحة عمل مستقلة لكل حادثة أو مشروع (محادثة وملاحظات خاصة) مع تقرير وتصدير.\n"
                 "• مكتبتي: اضغط 📌 تحت أي إجابة لحفظها، وابحث فيها وصدّرها.\n"
                 "• قوائم التحقق: 8 قوائم تفاعلية تعمل بلا اتصال (استجابة، فدية، تصيّد، تحصين...).\n\n"
                 "<b>⚙️ الإعدادات</b>\n"
                 "• أسلوب الرد (مختصر/متوازن/مفصّل)، الشخصية، اللغة، الذاكرة والتذكيرات.\n\n"
                 "<b>الأوامر:</b> /menu · /case · /notes · /checklist · /new · /stop · /id\n"
                 "<i>الأوامر القديمة مثل /url و/ioc ما زالت تعمل كاختصارات.</i>"),
        "admin_help": "\n\n👑 المدير: 👑 لوحة المدير في القائمة الرئيسية.",
        "sec_usage_decode": "الاستخدام: أرسل نصاً مموّهاً (Base64/Hex/URL).",
        "sec_usage_cvss": "الاستخدام: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "sec_usage_ip": "الاستخدام: عنوان IP أو CIDR، مثال 10.0.0.0/24",
        "sec_usage_defang": "الاستخدام: الصق نصاً يحتوي روابط أو نطاقات.",
        "sec_usage_sigma": "الاستخدام: صِف السلوك المراد كشفه.",
        "sec_cvss_bad": "⚠️ متجه CVSS غير صالح. يلزم AV AC PR UI S C I A، مثال:\nCVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "sec_ip_bad": "⚠️ ليس عنوان IP ولا CIDR صالحاً.",
        "sec_decode_head": "🔓 طبقات الفك:",
        "sec_decode_note": "ℹ️ النتائج معطّلة النقر. لا تشغّل أي شيء مفكوك قبل فحصه في بيئة معزولة.",
        "sec_genpass_out": "🎲 كلمة مرور ({n} حرفاً):\n{p}\n\nانسخها إلى مدير كلمات مرور. ستُحذف هذه الرسالة تلقائياً بعد دقيقة.",
    },
    "en": {
        "sec_usage_port": "🔌 Usage: /port 3389  or  /port 22,445  or  /port 20-25  or  /port ssh",
        "sec_usage_ts": "🕓 Usage: /ts 1700000000  or  /ts 2024-05-01T10:00:00Z  or  /ts now",
        "sec_usage_mitre": "🗺 Usage: /mitre T1059.001  or  /mitre Kerberoasting",
        "sec_port_none": "I do not know that port or service. Try a common number like 443 or a name like rdp.",
        "sec_port_head": "Ports and risks",
        "sec_ts_bad": "I could not read that timestamp. Send a number (Unix/FILETIME/WebKit), an ISO date, or now.",
        "sec_ts_decode": "Likely interpretations (UTC)",
        "sec_ts_encode": "Date conversion",
        "welcome": ("🛡 <b>Hi {name}! I'm DARWIN DZ</b>\nAn AI model specialised in cybersecurity.\n\n"
                    "💬 Just type your question\n"
                    "📎 or send a log / code / config file to analyse\n"
                    "🧰 or open the quick security tools on the buttons 👇"),
        "help": ("📖 <b>How to use the bot</b>\n\n"
                 "<b>💬 Chat</b>\n"
                 "• Type any security question and I answer directly.\n"
                 "• Under every answer: Retry · Continue · Shorter · Translate.\n"
                 "• ⏹ shows while I'm writing so you can stop the reply.\n\n"
                 "<b>🧰 Security tools</b> — local, instant, no credit\n"
                 "• Tap a tool, then send the input (link, text, hash, token…).\n\n"
                 "<b>🤖 AI assistant</b>\n"
                 "• CVE, hardening, incident response, log analysis, detection rules.\n"
                 "• Send a file with a caption to analyse it, or reply to a message to pass its text to a tool.\n\n"
                 "<b>🗂 Organisation</b>\n"
                 "• Cases: a separate workspace per incident or project (own chat and notes), with report and export.\n"
                 "• Library: tap 📌 under any answer to save it; search and export your notes.\n"
                 "• Checklists: 8 interactive offline lists (incident response, ransomware, phishing, hardening…).\n\n"
                 "<b>⚙️ Settings</b>\n"
                 "• Reply style (concise/balanced/detailed), persona, language, memory and reminders.\n\n"
                 "<b>Commands:</b> /menu · /case · /notes · /checklist · /new · /stop · /id\n"
                 "<i>Older commands such as /url and /ioc still work as shortcuts.</i>"),
        "admin_help": "\n\n👑 Admins: use 👑 Admin panel in the main menu.",
        "sec_usage_decode": "Usage: send an obfuscated string (Base64/Hex/URL).",
        "sec_usage_cvss": "Usage: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "sec_usage_ip": "Usage: an IP address or CIDR, e.g. 10.0.0.0/24",
        "sec_usage_defang": "Usage: paste text containing links or domains.",
        "sec_usage_sigma": "Usage: describe the behaviour to detect.",
        "sec_cvss_bad": "⚠️ Invalid CVSS vector. AV AC PR UI S C I A are required, e.g.\nCVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "sec_ip_bad": "⚠️ Not a valid IP address or CIDR.",
        "sec_decode_head": "🔓 Decoding layers:",
        "sec_decode_note": "ℹ️ Output is defanged. Never run decoded content before inspecting it in an isolated environment.",
        "sec_genpass_out": "🎲 Password ({n} chars):\n{p}\n\nCopy it into a password manager. This message deletes itself in one minute.",
    },
}
