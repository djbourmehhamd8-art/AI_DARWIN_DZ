"""Data for the extra tools menu (no imports, so ui.py and proext.py can both use it)."""

# kind, icon, Arabic, English, hint-Arabic, hint-English
UTILS = (
    ("calc", "🧮", "حاسبة", "Calculator", "🧮 أرسل عملية حسابية مثل: (12+8)*3 أو sqrt(144) أو 2^10", "🧮 Send an expression such as (12+8)*3, sqrt(144) or 2^10"),
    ("unit", "📏", "محوّل وحدات", "Unit converter", "📏 مثال: 10 km to mi — أو 100 c to f — أو 2 gib to mb", "📏 Example: 10 km to mi — or 100 c to f — or 2 gib to mb"),
    ("pct", "％", "نسبة مئوية", "Percentage", "％ أمثلة: 15% of 200 — أو 30 of 120 — أو 50 to 75 (نسبة التغيّر)", "％ Examples: 15% of 200 — or 30 of 120 — or 50 to 75 (change)"),
    ("json", "🧾", "منسّق JSON", "JSON formatter", "🧾 الصق JSON لتنسيقه والتحقق منه.", "🧾 Paste JSON to validate and pretty-print it."),
    ("regex", "🧩", "مختبر Regex", "Regex tester", "🧩 أرسل: النمط :: النص\nمثال: \\d+ :: abc 123 def 45", "🧩 Send: pattern :: text\nExample: \\d+ :: abc 123 def 45"),
    ("textstat", "🔤", "إحصاءات نص", "Text stats", "🔤 الصق نصاً لعدّ الكلمات والأحرف ووقت القراءة.", "🔤 Paste text to count words, characters and reading time."),
    ("uniq", "🧹", "إزالة التكرار", "Dedupe & sort", "🧹 الصق قائمة (سطر لكل عنصر) لإزالة المكرر وترتيبها.", "🧹 Paste a list (one item per line) to dedupe and sort it."),
    ("urlenc", "🔗", "ترميز URL", "URL encode/decode", "🔗 أرسل نصاً لترميزه، أو رابطاً مرمّزاً (%20) لفكّه.", "🔗 Send text to encode, or a percent-encoded string (%20) to decode."),
    ("color", "🎨", "محوّل ألوان", "Colour converter", "🎨 أرسل لوناً: #1f6feb أو 31 111 235", "🎨 Send a colour: #1f6feb or 31 111 235"),
    ("caseconv", "🔡", "تحويل الحالة", "Case converter", "🔡 أرسل عبارة لتحويلها إلى snake/camel/kebab…", "🔡 Send a phrase to convert to snake/camel/kebab…"),
    ("slug", "🏷", "رابط مختصر (Slug)", "Slugify", "🏷 أرسل عنواناً لتحويله إلى slug صالح للروابط.", "🏷 Send a title to turn into a URL slug."),
    ("roll", "🎲", "نرد / رقم عشوائي", "Dice / random", "🎲 أرسل: 2d6 — أو 50 (من 1 إلى 50) — أو 10 20 — أو coin", "🎲 Send: 2d6 — or 50 (1..50) — or 10 20 — or coin"),
    ("uuid", "🆔", "مولّد UUID", "UUID generator", "🆔 أرسل عدداً (1-10) أو أي نص لتوليد 3 معرّفات.", "🆔 Send a count (1-10) or anything for 3 identifiers."),
    ("csp", "🛡", "فاحص CSP", "CSP analyzer", "🛡 الصق سياسة Content-Security-Policy لفحص نقاط ضعفها.", "🛡 Paste a Content-Security-Policy to audit its weaknesses."),
    ("cookie", "🍪", "فاحص الكوكيز", "Cookie auditor", "🍪 الصق سطر Set-Cookie (القيمة لا تُعرض ولا تُخزَّن).", "🍪 Paste a Set-Cookie line (the value is never shown or stored)."),
    ("secheaders", "🧱", "تقييم ترويسات الأمان", "Security headers grade", "🧱 الصق ترويسات استجابة HTTP كاملة لتقييمها (A–F).", "🧱 Paste a full HTTP response header block to grade it (A–F)."),
    ("subnet", "🕸", "حاسبة الشبكات الفرعية", "Subnet calculator", "🕸 مثال: 192.168.1.10/24 — أو 10.0.0.0/24 /26 للتقسيم", "🕸 Example: 192.168.1.10/24 — or 10.0.0.0/24 /26 to split"),
    ("cron", "⏰", "مفسّر Cron", "Cron explainer", "⏰ مثال: */15 * * * * — أو 0 3 * * mon-fri — أو @daily", "⏰ Example: */15 * * * * — or 0 3 * * mon-fri — or @daily"),
    ("spf", "📨", "فاحص SPF", "SPF auditor", "📨 الصق سجل SPF (v=spf1 …) لفحصه: all وحد 10 عمليات بحث وmechanisms خطرة.", "📨 Paste an SPF record (v=spf1 …) to audit: all, the 10-lookup limit and risky mechanisms."),
    ("dmarc", "📬", "فاحص DMARC", "DMARC auditor", "📬 الصق سجل DMARC (v=DMARC1; p=…) لفحصه.", "📬 Paste a DMARC record (v=DMARC1; p=…) to audit it."),
    ("secrets", "🕵️", "كاشف الأسرار المسرّبة", "Leaked-secret scanner", "🕵️ الصق نصاً أو كوداً أو سجلاً: أبحث عن مفاتيح وتوكنات وكلمات مرور وأخفيها في النتيجة. سأحذف رسالتك.", "🕵️ Paste text, code or a log: I look for keys, tokens and passwords and mask them in the result. I delete your message."),
    ("sri", "🔒", "هاش SRI", "SRI hash", "🔒 الصق محتوى سكربت/CSS لحساب هاش Subresource Integrity.", "🔒 Paste a script/CSS body to compute its Subresource Integrity hash."),
    ("chmod", "🔑", "حاسبة chmod", "chmod calculator", "🔑 مثال: 755 — أو rwxr-xr-x — أو u=rwx,go=rx", "🔑 Example: 755 — or rwxr-xr-x — or u=rwx,go=rx"),
    ("cidrmatch", "🎯", "هل IP ضمن نطاق؟", "IP in CIDR?", "🎯 مثال: 10.1.2.3, 8.8.8.8 in 10.0.0.0/8, 192.168.0.0/16", "🎯 Example: 10.1.2.3, 8.8.8.8 in 10.0.0.0/8, 192.168.0.0/16"),
    ("ipconv", "🔁", "تحويل IP", "IP converter", "🔁 أرسل IP أو رقماً عشرياً أو 0x hex: أعرض الصيغ كلها والـ reverse pointer.", "🔁 Send an IP, a decimal number or 0x hex: every representation plus the reverse pointer."),
    ("useragent", "🧑\u200d💻", "محلّل User-Agent", "User-Agent parser", "🧑\u200d💻 الصق سلسلة User-Agent لمعرفة المتصفح والنظام وعلامات الأتمتة أو أدوات الفحص.", "🧑\u200d💻 Paste a User-Agent string for browser, OS and bot / scanner signals."),
    ("diff", "🔀", "مقارنة نصين", "Text diff", "🔀 أرسل النص الأول ثم سطراً فيه --- فقط ثم النص الثاني.", "🔀 Send the first text, a line with only ---, then the second text."),
    ("date", "📅", "حاسبة التواريخ", "Date calculator", "📅 أمثلة: 2026-01-01 to 2026-03-01 — أو today + 90d — أو 2026-12-25", "📅 Examples: 2026-01-01 to 2026-03-01 — or today + 90d — or 2026-12-25"),
)
UTIL_KINDS = tuple(k for k, *_ in UTILS)
UTIL_HINTS = {k: (ha, he) for k, _i, _a, _e_, ha, he in UTILS}
