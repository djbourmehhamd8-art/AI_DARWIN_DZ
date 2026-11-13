"""Offline, interactive security checklists. Progress is a bitmask carried in the button data (no storage)."""
from __future__ import annotations

# id: (icon, Arabic title, English title, [(Arabic item, English item), ...])
CHECKLISTS = {
    "ir": ("🚨", "الساعة الأولى في حادثة أمنية", "First hour of an incident", [
        ("حدّد المتأثّر ونطاق الحادثة وسجّل وقت الاكتشاف", "Identify what is affected and the scope; record detection time"),
        ("عيّن قائد الاستجابة وقناة اتصال آمنة منفصلة", "Name an incident lead and a separate, trusted comms channel"),
        ("اعزل الأجهزة المصابة عن الشبكة (لا تُطفئها قبل حفظ الذاكرة)", "Isolate affected hosts from the network (do not power off before memory capture)"),
        ("احفظ الأدلة: لقطة ذاكرة، سجلات، صور قرص، مع سلسلة حيازة", "Preserve evidence: memory, logs, disk images, with chain of custody"),
        ("غيّر كلمات المرور وألغِ الجلسات والمفاتيح للحسابات المعرّضة", "Rotate passwords, sessions and keys for exposed accounts"),
        ("احجب المؤشرات المعروفة (IP/نطاقات/هاشات) على الجدار والبريد", "Block known indicators (IPs/domains/hashes) at firewall and mail"),
        ("أبلغ أصحاب القرار والقانونية والامتثال حسب السياسة", "Notify management, legal and compliance per policy"),
        ("وثّق كل إجراء بوقته لإعداد التقرير والدروس المستفادة", "Log every action with a timestamp for the report and lessons learned"),
    ]),
    "ransom": ("🔒", "الاستجابة لبرمجية فدية", "Ransomware response", [
        ("افصل الأجهزة المصابة والمشاركات الشبكية فوراً", "Disconnect infected hosts and network shares immediately"),
        ("أوقف المزامنة السحابية وعطّل حسابات الخدمة المشتبهة", "Pause cloud sync and disable suspected service accounts"),
        ("تحقق من سلامة النسخ الاحتياطية وعزلها عن الشبكة", "Verify backups are intact and isolated from the network"),
        ("حدّد العائلة والامتداد وملاحظة الفدية دون تنفيذ أي ملف", "Identify the family/extension and ransom note without executing anything"),
        ("ابحث عن نقطة الدخول (RDP، تصيّد، ثغرة VPN) واغلقها", "Find the entry point (RDP, phishing, VPN flaw) and close it"),
        ("افحص الحركة الجانبية وحسابات المدير الجديدة قبل الاستعادة", "Hunt for lateral movement and new admin accounts before restoring"),
        ("استعد من نسخ نظيفة بعد إعادة بناء الأجهزة، وغيّر كل الأسرار", "Restore from clean backups on rebuilt hosts; rotate all secrets"),
        ("أبلغ الجهات التنظيمية والتأمين وراجع قرار الدفع مع القانونية", "Notify regulators/insurer; review any payment decision with legal"),
    ]),
    "phish": ("🎣", "فرز بريد تصيّد مُبلَّغ عنه", "Reported phishing triage", [
        ("احصل على الرسالة الأصلية كاملة بترويستها (.eml) لا لقطة شاشة", "Get the original message with full headers (.eml), not a screenshot"),
        ("افحص SPF وDKIM وDMARC ومسار Received والمُرسِل الحقيقي", "Check SPF, DKIM, DMARC, the Received chain and the real sender"),
        ("استخرج الروابط والمرفقات وعطّلها (defang) قبل أي فحص", "Extract and defang links and attachments before any analysis"),
        ("افحص الروابط والهاشات في بيئة معزولة أو خدمة سمعة", "Check links/hashes in a sandbox or reputation service"),
        ("ابحث عن المستلمين الآخرين وأزل الرسالة من كل الصناديق", "Find other recipients and purge the message from all mailboxes"),
        ("إن نقر أحدهم: اعزل جهازه وغيّر كلمة المرور وألغِ جلساته", "If someone clicked: isolate the device, reset password, revoke sessions"),
        ("احجب النطاق والمرسل والروابط على البوابة", "Block the sender, domain and URLs at the gateway"),
        ("أبلغ المستخدم بالنتيجة وسجّل الحالة", "Tell the reporter the outcome and record the case"),
    ]),
    "linux": ("🐧", "تحصين خادم لينكس", "Linux server hardening", [
        ("حدّث النظام وفعّل التحديثات الأمنية التلقائية", "Patch the system and enable automatic security updates"),
        ("SSH: مفاتيح فقط، منع root وكلمات المرور، وقيّد المستخدمين", "SSH: keys only, no root/password login, restrict users"),
        ("جدار ناري افتراضه المنع (ufw/nftables) ومنافذ لازمة فقط", "Default-deny firewall (ufw/nftables), only needed ports"),
        ("فعّل fail2ban أو ما يماثله للحماية من التخمين", "Enable fail2ban or equivalent against brute force"),
        ("أزل الحزم والخدمات غير اللازمة وتحقق من المنافذ المفتوحة (ss -tlnp)", "Remove unneeded packages/services; audit open ports (ss -tlnp)"),
        ("صلاحيات sudo بأدنى حد، وراجع ملفات SUID وصلاحيات /etc", "Least-privilege sudo; review SUID files and /etc permissions"),
        ("فعّل auditd وأرسل السجلات إلى خادم مركزي", "Enable auditd and ship logs to a central server"),
        ("نسخ احتياطي مُختبَر ومُعزول، وأقفل التمهيد/القرص حسب الحاجة", "Tested, isolated backups; encrypt disks where appropriate"),
    ]),
    "win": ("🪟", "تحصين جهاز ويندوز", "Windows endpoint hardening", [
        ("فعّل BitLocker وSecure Boot وTPM", "Enable BitLocker, Secure Boot and TPM"),
        ("حدّث ويندوز والتطبيقات وأزل ما لا يلزم", "Patch Windows and apps; remove unneeded software"),
        ("المستخدم اليومي بلا صلاحيات مدير، وLAPS لحساب المدير المحلي", "Daily user without admin rights; LAPS for the local admin"),
        ("عطّل SMBv1 وWDigest، وقيّد RDP خلف VPN مع NLA وMFA", "Disable SMBv1 and WDigest; RDP only behind VPN with NLA and MFA"),
        ("فعّل Defender وقواعد ASR وحماية التلاعب (Tamper Protection)", "Enable Defender, ASR rules and Tamper Protection"),
        ("فعّل تدقيق سطر الأوامر (4688) وSysmon وأرسل السجلات مركزياً", "Enable command-line auditing (4688), Sysmon and central logging"),
        ("قيّد PowerShell (Constrained Language/تسجيل الكتل) وAppLocker/WDAC", "Constrain PowerShell (logging, CLM) and use AppLocker/WDAC"),
        ("اضبط الجدار الناري وعطّل الخدمات والمشاركات غير اللازمة", "Tune the firewall; disable unneeded services and shares"),
    ]),
    "cloud": ("☁️", "خط أساس أمان الحساب السحابي", "Cloud account baseline", [
        ("فعّل MFA لكل المستخدمين وأقفل حساب الجذر/المالك وابتعد عن استخدامه اليومي", "Enforce MFA for everyone; lock away the root/owner account"),
        ("صلاحيات IAM بأدنى حد؛ لا مفاتيح وصول دائمة لحسابات بشرية", "Least-privilege IAM; no long-lived keys for humans"),
        ("فعّل تسجيل النشاط (CloudTrail/Activity Log/Audit Logs) وأرسله لمخزن محمي", "Enable activity logging (CloudTrail/Activity Log/Audit Logs) to protected storage"),
        ("ابحث عن مخازن/قواعد بيانات/مفاتيح عامة مكشوفة", "Find publicly exposed buckets, databases and keys"),
        ("شفّر البيانات أثناء النقل وعند التخزين وأدر المفاتيح (KMS)", "Encrypt data in transit and at rest; manage keys (KMS)"),
        ("قيّد مجموعات الأمان/الجدار: لا 0.0.0.0/0 على SSH/RDP/قواعد البيانات", "Restrict security groups: no 0.0.0.0/0 on SSH/RDP/databases"),
        ("فعّل تنبيهات الشذوذ والتكلفة (GuardDuty/Defender for Cloud/SCC)", "Enable threat and cost anomaly alerts (GuardDuty/Defender for Cloud/SCC)"),
        ("افحص أسرار الكود والصور (secret scanning) وبدّل ما تسرّب", "Scan code/images for secrets and rotate anything leaked"),
    ]),
    "web": ("🌐", "أمان تطبيق ويب قبل الإطلاق", "Web app pre-release security", [
        ("التحقق من المدخلات واستعلامات مُعلَّمة (منع SQLi) وترميز المخرجات (XSS)", "Validate input; parameterised queries (SQLi); encode output (XSS)"),
        ("المصادقة: تجزئة كلمات المرور (Argon2/bcrypt)، MFA، حدّ المحاولات", "Auth: Argon2/bcrypt hashing, MFA, rate limiting"),
        ("التفويض على الخادم لكل طلب (منع IDOR) لا على الواجهة فقط", "Server-side authorisation on every request (IDOR), not only in the UI"),
        ("ترويسات: CSP وHSTS وX-Content-Type-Options وSameSite للكوكيز", "Headers: CSP, HSTS, X-Content-Type-Options, SameSite cookies"),
        ("حماية CSRF وSSRF وتحميل الملفات (النوع والحجم والمسار)", "CSRF, SSRF and file-upload controls (type, size, path)"),
        ("أسرار خارج الكود ومحدّثة؛ افحص الاعتماديات (SCA) وSBOM", "Secrets out of code; scan dependencies (SCA) and keep an SBOM"),
        ("أخطاء عامة للمستخدم وتفاصيل في السجلات فقط؛ سجّل الأحداث الأمنية", "Generic user errors, details only in logs; log security events"),
        ("اختبار SAST/DAST ومراجعة OWASP Top 10 وخطة تصحيح قبل الإطلاق", "SAST/DAST, OWASP Top 10 review and a patch plan before launch"),
    ]),
    "acct": ("👤", "استرداد حساب مُخترَق", "Compromised account recovery", [
        ("غيّر كلمة المرور من جهاز نظيف وبكلمة جديدة فريدة", "Change the password from a clean device to a new unique one"),
        ("سجّل الخروج من كل الجلسات والأجهزة وألغِ التطبيقات المرتبطة", "Sign out everywhere and revoke connected apps"),
        ("فعّل المصادقة الثنائية (تطبيق أو مفتاح أمان لا SMS إن أمكن)", "Enable 2FA (app or security key, not SMS if possible)"),
        ("راجع قواعد إعادة توجيه البريد والتوقيع وعناوين الاسترداد", "Review mail forwarding rules, signature and recovery addresses"),
        ("غيّر كلمات المرور في الحسابات التي تشاركها نفس الكلمة", "Change passwords on accounts that reused it"),
        ("افحص الجهاز بحثاً عن برمجيات خبيثة قبل تسجيل الدخول مجدداً", "Scan the device for malware before signing in again"),
        ("نبّه جهات اتصالك بأي رسائل مريبة أُرسلت باسمك", "Warn contacts about suspicious messages sent in your name"),
        ("إن وُجد ضرر مالي: بلّغ البنك وجمّد البطاقات واحتفظ بالأدلة", "If money is involved: tell your bank, freeze cards, keep evidence"),
    ]),
}


def order() -> list:
    return list(CHECKLISTS)


def full_mask(cid: int | str) -> int:
    return (1 << len(CHECKLISTS[cid][3])) - 1


def render(cid: str, mask: int, lang: str) -> str:
    """HTML body of one checklist with its progress."""
    import html
    icon, ar, en, items = CHECKLISTS[cid]
    done = bin(mask & full_mask(cid)).count("1")
    n = len(items)
    bar = "▰" * round(done * 10 / n) + "▱" * (10 - round(done * 10 / n))
    lines = [f"{icon} <b>{html.escape(ar if lang == 'ar' else en)}</b>", f"{bar}  {done}/{n} ({done * 100 // n}%)", ""]
    for i, (a, e) in enumerate(items):
        mark = "☑️" if mask >> i & 1 else "⬜"
        text = html.escape(a if lang == "ar" else e)
        lines.append(f"{mark} {i + 1}. " + (f"<s>{text}</s>" if mask >> i & 1 else text))
    return "\n".join(lines)


def to_markdown(cid: str, mask: int, lang: str) -> str:
    icon, ar, en, items = CHECKLISTS[cid]
    lines = [f"{icon} {ar if lang == 'ar' else en}", ""]
    for i, (a, e) in enumerate(items):
        lines.append(f"- [{'x' if mask >> i & 1 else ' '}] {a if lang == 'ar' else e}")
    return "\n".join(lines)
