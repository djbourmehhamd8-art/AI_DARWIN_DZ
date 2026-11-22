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
)
UTIL_KINDS = tuple(k for k, *_ in UTILS)
UTIL_HINTS = {k: (ha, he) for k, _i, _a, _e_, ha, he in UTILS}
