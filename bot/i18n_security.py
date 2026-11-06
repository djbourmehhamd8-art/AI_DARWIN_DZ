"""Branding, help and security-feature strings (ar/en)."""

SECURITY_STRINGS = {
    "ar": {
        "welcome": ("🛡 أهلاً {name}! أنا DARWIN DZ\nنموذج ذكاء اصطناعي متخصص في الأمن السيبراني.\n\n"
                    "اسألني عن أي تهديد أو حادثة أو ثغرة، أو أرسل سجلاً/كوداً/ملف إعدادات لتحليله.\n"
                    "🧰 /sec أدوات الأمن · /menu الإعدادات · /help كل الأوامر"),
        "about": ("🛡 DARWIN DZ v{ver}\nنموذج ذكاء اصطناعي متخصص في الأمن السيبراني: دفاع، استجابة للحوادث، "
                  "استخبارات تهديدات، أمن تطبيقات وتوعية.\n\n"
                  "🔒 خصوصيتك: تُحجب المفاتيح والتوكنات التي تلصقها قبل حفظها أو إرسالها للنموذج، "
                  "وكلمات المرور المُحلَّلة لا تُخزَّن أبداً."),
        "help": (
            "📖 الأوامر\n\n"
            "🛡 أمن سيبراني\n"
            "/sec — لوحة أدوات الأمن\n"
            "/url <رابط> — فحص احتيال الرابط (دون زيارته)\n"
            "/ioc <نص> — استخراج المؤشرات (IP, نطاقات, هاشات, CVE)\n"
            "/pass <كلمة> — قوة كلمة المرور + فحص التسريبات\n"
            "/genpass [طول] — توليد كلمة مرور قوية\n"
            "/hash <نص|هاش> — حساب الهاشات أو تحديد نوع الهاش\n"
            "/jwt <توكن> — فك وتدقيق JWT\n"
            "/headers <ترويسة البريد> — كشف انتحال البريد\n"
            "/b64 <نص> — ترميز/فك Base64\n"
            "/cve <CVE-ID> — شرح ثغرة للمدافع\n"
            "/harden <نظام> — قائمة تحصين\n"
            "/ir <وصف الحادثة> — خطة استجابة\n"
            "/explain <مصطلح> — شرح مفهوم أمني\n"
            "/analyze <نص> — تحليل سجل/تنبيه/كود (أو بالرد على رسالة)\n\n"
            "💬 المحادثة\n"
            "/new /retry /stop /persona /temp /system /lang /export\n"
            "/ask /summary /tr /remember /memory /forget\n"
            "/remind /reminders /unremind /usage /quota /about /id\n\n"
            "📎 أرسل ملف سجل أو إعدادات أو كود (txt, log, conf, py, json...) مع تعليق وسأحلله.\n"
            "💡 الأوامر الأمنية تقبل الرد على رسالة بدل كتابة النص."),
        "admin_help": ("\n\n👑 المدير:\n/stats /users /audit\n/broadcast <نص>\n/ban <id> /unban <id>\n"
                       "/allow <id> /disallow <id>\n/backup — نسخة قاعدة البيانات"),
        "sec_menu": "🧰 أدوات الأمن (محلية وسريعة، دون استهلاك رصيد):",
        "sec_url": "🔗 فحص رابط", "sec_ioc": "🎯 مؤشرات IOC", "sec_pass": "🔐 كلمة مرور",
        "sec_genpass": "🎲 توليد كلمة", "sec_hash": "#️⃣ هاش", "sec_jwt": "🪪 JWT",
        "sec_headers": "📧 ترويسة بريد", "sec_cve": "🐞 CVE", "sec_harden": "🧱 تحصين", "sec_ir": "🚨 حادثة",
        "sec_usage_url": "الاستخدام: /url <رابط> (أو بالرد على رسالة تحتوي الرابط)",
        "sec_usage_ioc": "الاستخدام: /ioc <نص> (أو بالرد على رسالة)",
        "sec_usage_pass": "الاستخدام: /pass <كلمة المرور>\n⚠️ جرّب كلمة مشابهة، لا تستخدم كلمة حقيقية.",
        "sec_usage_hash": "الاستخدام: /hash <نص أو هاش>",
        "sec_usage_jwt": "الاستخدام: /jwt <التوكن>",
        "sec_usage_headers": "الاستخدام: الصق ترويسة البريد الخام بعد /headers (أو ارفعها كملف نصي/بالرد عليها).",
        "sec_usage_b64": "الاستخدام: /b64 <نص> — يفك الترميز إن كان Base64 وإلا يرمّز.",
        "sec_usage_cve": "الاستخدام: /cve CVE-2024-3094",
        "sec_usage_harden": "الاستخدام: /harden <نظام>\nمثال: /harden Ubuntu 24 SSH server",
        "sec_usage_ir": "الاستخدام: /ir <وصف الحادثة>\nمثال: /ir حساب الموظف أرسل رسائل تصيّد",
        "sec_usage_explain": "الاستخدام: /explain <مصطلح>\nمثال: /explain Kerberoasting",
        "sec_usage_analyze": "الاستخدام: /analyze <نص> أو بالرد على رسالة/ملف.",
        "sec_bad_cve": "⚠️ صيغة غير صحيحة. مثال: CVE-2024-3094",
        "sec_jwt_bad": "⚠️ هذا ليس JWT صالحاً.",
        "sec_headers_bad": "⚠️ لم أجد ترويسات بريد صالحة.",
        "sec_no_ioc": "لم أجد مؤشرات في النص.",
        "sec_ioc_head": "🎯 المؤشرات المستخرجة (محمية من النقر):",
        "sec_hash_ident": "🔎 الأنواع المحتملة: {c}",
        "sec_hash_weak": "⚠️ هذا النوع ضعيف/قديم لتخزين كلمات المرور. استخدم bcrypt أو Argon2.",
        "sec_hash_unknown": "لم أتعرف على نوع الهاش.",
        "sec_b64_dec": "🔓 فك Base64:\n{x}",
        "sec_b64_enc": "🔒 Base64:\n{x}",
        "sec_genpass_out": "🎲 كلمة مرور ({n} حرفاً):\n{p}\n\nانسخها إلى مدير كلمات مرور، ثم احذف هذه الرسالة.",
        "secret_warn": ("🚨 اكتشفت سراً حساساً في رسالتك ({k}). حجبته قبل إرساله أو حفظه. "
                        "إن كان حقيقياً فاعتبره مسرّباً وبدّله فوراً."),
        "file_default_prompt": "حلّل هذا الملف أمنياً: المخاطر، الخطورة، والإصلاحات.",
        "summary_instr": "لخّص المحادثة أعلاه في نقاط موجزة بنفس لغتها.",
        "audit_head": "🧾 آخر الأحداث:",
    },
    "en": {
        "welcome": ("🛡 Hi {name}! I'm DARWIN DZ\nAn AI model specialised in cybersecurity.\n\n"
                    "Ask me about any threat, incident or vulnerability, or send a log / code / config file to analyse.\n"
                    "🧰 /sec security tools · /menu settings · /help all commands"),
        "about": ("🛡 DARWIN DZ v{ver}\nAI model specialised in cybersecurity: defence, incident response, "
                  "threat intelligence, application security and awareness.\n\n"
                  "🔒 Privacy: API keys and tokens you paste are masked before being stored or sent to the model, "
                  "and analysed passwords are never stored."),
        "help": (
            "📖 Commands\n\n"
            "🛡 Cybersecurity\n"
            "/sec — security toolbox\n"
            "/url <link> — phishing check (never visits it)\n"
            "/ioc <text> — extract IOCs (IP, domains, hashes, CVE)\n"
            "/pass <password> — strength + breach check\n"
            "/genpass [length] — generate a strong password\n"
            "/hash <text|hash> — compute hashes or identify a hash\n"
            "/jwt <token> — decode and audit a JWT\n"
            "/headers <raw headers> — spot email spoofing\n"
            "/b64 <text> — Base64 encode/decode\n"
            "/cve <CVE-ID> — explain a vulnerability for defenders\n"
            "/harden <system> — hardening checklist\n"
            "/ir <incident> — incident-response playbook\n"
            "/explain <term> — explain a security concept\n"
            "/analyze <text> — analyse a log/alert/code (or reply to a message)\n\n"
            "💬 Chat\n"
            "/new /retry /stop /persona /temp /system /lang /export\n"
            "/ask /summary /tr /remember /memory /forget\n"
            "/remind /reminders /unremind /usage /quota /about /id\n\n"
            "📎 Send a log, config or code file (txt, log, conf, py, json...) with a caption and I'll analyse it.\n"
            "💡 Security commands also work as a reply to a message."),
        "admin_help": ("\n\n👑 Admin:\n/stats /users /audit\n/broadcast <text>\n/ban <id> /unban <id>\n"
                       "/allow <id> /disallow <id>\n/backup — database copy"),
        "sec_menu": "🧰 Security toolbox (local & instant, no credit used):",
        "sec_url": "🔗 URL check", "sec_ioc": "🎯 IOC extract", "sec_pass": "🔐 Password",
        "sec_genpass": "🎲 Generate", "sec_hash": "#️⃣ Hash", "sec_jwt": "🪪 JWT",
        "sec_headers": "📧 Email headers", "sec_cve": "🐞 CVE", "sec_harden": "🧱 Harden", "sec_ir": "🚨 Incident",
        "sec_usage_url": "Usage: /url <link> (or reply to a message containing it)",
        "sec_usage_ioc": "Usage: /ioc <text> (or reply to a message)",
        "sec_usage_pass": "Usage: /pass <password>\n⚠️ Try a similar one, never a real password.",
        "sec_usage_hash": "Usage: /hash <text or hash>",
        "sec_usage_jwt": "Usage: /jwt <token>",
        "sec_usage_headers": "Usage: paste raw email headers after /headers (or upload them as a text file / reply to them).",
        "sec_usage_b64": "Usage: /b64 <text>: decodes if it's Base64, otherwise encodes.",
        "sec_usage_cve": "Usage: /cve CVE-2024-3094",
        "sec_usage_harden": "Usage: /harden <system>\nExample: /harden Ubuntu 24 SSH server",
        "sec_usage_ir": "Usage: /ir <incident>\nExample: /ir employee account sent phishing emails",
        "sec_usage_explain": "Usage: /explain <term>\nExample: /explain Kerberoasting",
        "sec_usage_analyze": "Usage: /analyze <text> or reply to a message/file.",
        "sec_bad_cve": "⚠️ Invalid format. Example: CVE-2024-3094",
        "sec_jwt_bad": "⚠️ Not a valid JWT.",
        "sec_headers_bad": "⚠️ No valid email headers found.",
        "sec_no_ioc": "No indicators found in the text.",
        "sec_ioc_head": "🎯 Extracted indicators (defanged):",
        "sec_hash_ident": "🔎 Possible types: {c}",
        "sec_hash_weak": "⚠️ Weak/legacy for password storage. Use bcrypt or Argon2.",
        "sec_hash_unknown": "Could not identify the hash type.",
        "sec_b64_dec": "🔓 Base64 decoded:\n{x}",
        "sec_b64_enc": "🔒 Base64:\n{x}",
        "sec_genpass_out": "🎲 Password ({n} chars):\n{p}\n\nCopy it into a password manager, then delete this message.",
        "secret_warn": ("🚨 I detected a sensitive secret in your message ({k}). I masked it before sending or storing it. "
                        "If it was real, treat it as leaked and rotate it now."),
        "file_default_prompt": "Analyse this file for security: risks, severity and fixes.",
        "summary_instr": "Summarize the conversation above in concise bullet points, in its language.",
        "audit_head": "🧾 Recent events:",
    },
}
