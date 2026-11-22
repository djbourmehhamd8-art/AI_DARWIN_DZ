"""Curated catalogue of defensive / dual-use security tools and security-focused Linux distributions.
Official project sites only. Pure data + tiny helpers (searchable offline)."""
from __future__ import annotations

import html

# category key -> (icon, Arabic title, English title, [(name, Arabic note, English note, official URL)])
CATALOG = {
    "distros": ("🐧", "توزيعات لينكس الأمنية", "Security Linux distributions", [
        ("Kali Linux", "اختبار اختراق مصرّح وتقييم أمني (الأشهر)", "Authorised pentesting & assessment (most popular)", "https://www.kali.org"),
        ("Parrot Security", "بديل خفيف لكالي مع أدوات خصوصية وتحقيق", "Lighter Kali alternative with privacy & forensics tools", "https://parrotsec.org"),
        ("BlackArch", "مبني على Arch بمئات الأدوات للمتقدمين", "Arch-based with hundreds of tools for advanced users", "https://blackarch.org"),
        ("Security Onion", "مراقبة الشبكة والكشف: Zeek وSuricata وElastic", "Network monitoring & detection: Zeek, Suricata, Elastic", "https://securityonionsolutions.com"),
        ("REMnux", "تحليل البرمجيات الخبيثة على لينكس", "Malware analysis toolkit on Linux", "https://remnux.org"),
        ("FLARE VM", "بيئة ويندوز لتحليل البرمجيات الخبيثة والهندسة العكسية", "Windows environment for malware analysis & reverse engineering", "https://github.com/mandiant/flare-vm"),
        ("SIFT Workstation", "تحقيق جنائي رقمي من SANS", "SANS digital forensics workstation", "https://www.sans.org/tools/sift-workstation/"),
        ("CAINE", "توزيعة تحقيق جنائي رقمي", "Digital forensics live distribution", "https://www.caine-live.net"),
        ("Tails", "نظام يُقلع من USB ويمرّر الاتصال عبر Tor", "Amnesic live system routing traffic through Tor", "https://tails.net"),
        ("Whonix", "عزل كامل للاتصال عبر Tor باستخدام آلتين افتراضيتين", "Tor isolation with a gateway + workstation VM pair", "https://www.whonix.org"),
        ("Qubes OS", "عزل التطبيقات في آلات افتراضية منفصلة", "Security by compartmentalisation with VMs", "https://www.qubes-os.org"),
    ]),
    "network": ("🌐", "الشبكات والمراقبة", "Network & monitoring", [
        ("Wireshark", "تحليل الحزم الأشهر", "The standard packet analyser", "https://www.wireshark.org"),
        ("Zeek", "تحليل حركة الشبكة وتوليد سجلات غنية", "Network analysis framework producing rich logs", "https://zeek.org"),
        ("Suricata", "كشف ومنع التسلل (IDS/IPS) عالي الأداء", "High-performance IDS/IPS", "https://suricata.io"),
        ("Snort", "نظام كشف ومنع تسلل كلاسيكي", "Classic IDS/IPS", "https://www.snort.org"),
        ("Nmap", "اكتشاف الشبكات والخدمات (على أنظمتك أو بإذن)", "Network & service discovery (your own systems or with permission)", "https://nmap.org"),
        ("tcpdump", "التقاط الحزم من سطر الأوامر", "Command-line packet capture", "https://www.tcpdump.org"),
        ("Arkime", "التقاط وفهرسة الحزم كاملة للتحقيق", "Full packet capture and search", "https://arkime.com"),
        ("WireGuard", "VPN حديث وسريع وبسيط", "Modern, fast, simple VPN", "https://www.wireguard.com"),
    ]),
    "web": ("🕸", "أمن الويب والتطبيقات", "Web & application security", [
        ("Burp Suite", "اختبار أمان تطبيقات الويب (Community مجانية)", "Web app security testing (free Community edition)", "https://portswigger.net/burp"),
        ("OWASP ZAP", "ماسح ووكيل مفتوح المصدر لتطبيقات الويب", "Open-source web scanner and proxy", "https://www.zaproxy.org"),
        ("mitmproxy", "وكيل لاعتراض وفحص حركة HTTP(S) في الاختبار", "Interactive HTTPS proxy for testing", "https://mitmproxy.org"),
        ("Nuclei", "فحص ثغرات معروفة عبر قوالب YAML", "Template-based scanning for known issues", "https://projectdiscovery.io/nuclei"),
        ("testssl.sh", "فحص إعدادات TLS للخوادم من سطر الأوامر", "Command-line TLS configuration checker", "https://testssl.sh"),
        ("SSL Labs", "تقييم إعدادات TLS لموقع عام", "Public TLS grading for a website", "https://www.ssllabs.com/ssltest/"),
        ("Mozilla Observatory", "فحص رؤوس الأمان وأفضل الممارسات", "Security headers and best-practice scan", "https://developer.mozilla.org/en-US/observatory"),
        ("OWASP Top 10", "أخطر مخاطر تطبيقات الويب", "Most critical web application risks", "https://owasp.org/www-project-top-ten/"),
    ]),
    "dfir": ("🔬", "التحقيق الجنائي والاستجابة", "Forensics & incident response", [
        ("Autopsy / Sleuth Kit", "تحليل أقراص وأنظمة ملفات", "Disk & file-system forensics", "https://www.sleuthkit.org"),
        ("Volatility", "تحليل الذاكرة (RAM) الجنائي", "Memory forensics framework", "https://volatilityfoundation.org"),
        ("Velociraptor", "جمع أدلة وصيد تهديدات عبر الأجهزة", "Endpoint visibility, collection and hunting", "https://docs.velociraptor.app"),
        ("Plaso / log2timeline", "بناء خط زمني من آثار النظام", "Super timeline from system artefacts", "https://plaso.readthedocs.io"),
        ("Timesketch", "تحليل الخطوط الزمنية بشكل تعاوني", "Collaborative timeline analysis", "https://timesketch.org"),
        ("Chainsaw", "بحث سريع في سجلات أحداث ويندوز بقواعد Sigma", "Fast Windows event-log hunting with Sigma", "https://github.com/WithSecureLabs/chainsaw"),
        ("Hayabusa", "كشف تهديدات وخط زمني من سجلات ويندوز", "Windows event-log threat hunting & timeline", "https://github.com/Yamato-Security/hayabusa"),
        ("Eric Zimmerman's tools", "أدوات تحليل آثار ويندوز (Registry, MFT, Prefetch…)", "Windows artefact parsers (Registry, MFT, Prefetch…)", "https://ericzimmerman.github.io"),
    ]),
    "malware": ("🦠", "تحليل البرمجيات الخبيثة", "Malware analysis", [
        ("Ghidra", "هندسة عكسية مفتوحة المصدر من NSA", "Open-source reverse engineering suite", "https://ghidra-sre.org"),
        ("Cutter / Rizin", "واجهة رسومية للهندسة العكسية", "Reverse engineering GUI", "https://cutter.re"),
        ("x64dbg", "مُنقّح (debugger) لويندوز", "Windows debugger", "https://x64dbg.com"),
        ("CyberChef", "«سكين الجيش السويسري» لفك الترميز والتحليل", "The cyber Swiss-army knife for decoding & analysis", "https://gchq.github.io/CyberChef/"),
        ("YARA", "قواعد لوصف عائلات البرمجيات الخبيثة", "Rules to describe malware families", "https://virustotal.github.io/yara/"),
        ("Detect It Easy", "تحديد المُعبِّئات والمترجمات للملفات", "Packer / compiler identification", "https://github.com/horsicq/Detect-It-Easy"),
        ("CAPE Sandbox", "صندوق رمل لتحليل سلوك البرمجيات الخبيثة", "Malware sandbox with config extraction", "https://www.capesandbox.com"),
        ("ANY.RUN", "صندوق رمل تفاعلي عبر المتصفح", "Interactive online sandbox", "https://any.run"),
    ]),
    "soc": ("🛡", "مركز العمليات SOC والكشف", "SOC & detection", [
        ("Wazuh", "منصة SIEM/XDR مفتوحة المصدر", "Open-source SIEM / XDR", "https://wazuh.com"),
        ("Elastic Security", "SIEM وكشف على Elastic Stack", "SIEM and detection on the Elastic Stack", "https://www.elastic.co/security"),
        ("Graylog", "إدارة وتحليل السجلات", "Log management and analysis", "https://graylog.org"),
        ("Sigma", "صيغة موحّدة لقواعد الكشف تُترجم لأي SIEM", "Vendor-neutral detection rule format", "https://github.com/SigmaHQ/sigma"),
        ("osquery", "استعلام حالة الأجهزة بلغة SQL", "Query endpoints with SQL", "https://osquery.io"),
        ("Sysmon", "تسجيل مفصّل لأنشطة ويندوز", "Detailed Windows activity logging", "https://learn.microsoft.com/sysinternals/downloads/sysmon"),
        ("Falco", "كشف سلوك مشبوه وقت التشغيل في الحاويات", "Runtime threat detection for containers", "https://falco.org"),
        ("CrowdSec", "حظر تعاوني للعناوين المسيئة", "Collaborative IP reputation & blocking", "https://www.crowdsec.net"),
        ("Fail2ban", "حظر تلقائي لمحاولات الدخول الفاشلة", "Automatic banning of repeated failed logins", "https://github.com/fail2ban/fail2ban"),
        ("MISP", "منصة مشاركة مؤشرات التهديد", "Threat-intelligence sharing platform", "https://www.misp-project.org"),
        ("OpenCTI", "إدارة استخبارات التهديدات", "Cyber threat intelligence platform", "https://www.opencti.io"),
    ]),
    "intel": ("🕵️", "استخبارات التهديدات والتحقق", "Threat intelligence & lookups", [
        ("VirusTotal", "فحص ملفات وروابط ونطاقات بعشرات المحركات", "Scan files, URLs, domains with many engines", "https://www.virustotal.com"),
        ("AbuseIPDB", "سمعة عناوين IP", "IP reputation database", "https://www.abuseipdb.com"),
        ("URLhaus", "روابط توزّع برمجيات خبيثة", "Malware distribution URLs", "https://urlhaus.abuse.ch"),
        ("MalwareBazaar", "عينات وهاشات برمجيات خبيثة", "Malware sample & hash sharing", "https://bazaar.abuse.ch"),
        ("ThreatFox", "مؤشرات اختراق IOC", "IOC sharing platform", "https://threatfox.abuse.ch"),
        ("AlienVault OTX", "مؤشرات تهديد من المجتمع", "Community threat indicators", "https://otx.alienvault.com"),
        ("GreyNoise", "تمييز ضجيج الإنترنت عن الهجمات المستهدفة", "Separates internet background noise from targeted attacks", "https://www.greynoise.io"),
        ("Shodan", "محرك بحث للأجهزة المتصلة (تحقق من بصمتك أنت)", "Search engine for internet-exposed devices (check your own exposure)", "https://www.shodan.io"),
        ("Censys", "رؤية الأصول المكشوفة على الإنترنت", "Internet-wide asset visibility", "https://censys.io"),
        ("crt.sh", "سجل شهادات TLS الشفاف (اكتشاف النطاقات الفرعية والتصيّد)", "Certificate transparency search (subdomains, look-alike domains)", "https://crt.sh"),
        ("MITRE ATT&CK", "قاعدة معرفة تقنيات المهاجمين", "Adversary tactics and techniques knowledge base", "https://attack.mitre.org"),
        ("NVD", "قاعدة الثغرات الوطنية الأمريكية", "US National Vulnerability Database", "https://nvd.nist.gov"),
        ("CISA KEV", "الثغرات المستغَلّة فعلياً", "Known Exploited Vulnerabilities catalogue", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
        ("Have I Been Pwned", "هل ظهر بريدك في تسريبات؟", "Has your email appeared in a breach?", "https://haveibeenpwned.com"),
    ]),
    "radio": ("📻", "الراديو و SDR والاستقبال", "Radio, SDR & reception (receive-only unless licensed)", [
        ("RTL-SDR", "مستقبل SDR رخيص ومرجع المجتمع", "Cheap SDR receiver and community reference", "https://www.rtl-sdr.com"),
        ("SDR++", "برنامج SDR خفيف ومتعدد المنصات", "Lightweight cross-platform SDR software", "https://github.com/AlexandreRouma/SDRPlusPlus"),
        ("GQRX", "مستقبل SDR على لينكس وماك", "SDR receiver for Linux and macOS", "https://www.gqrx.dk"),
        ("GNU Radio", "بناء معالجات إشارة لاسلكية", "Build radio signal-processing flows", "https://www.gnuradio.org"),
        ("Universal Radio Hacker", "تحليل بروتوكولات لاسلكية للأجهزة", "Analyse wireless protocols of devices", "https://github.com/jopohl/urh"),
        ("inspectrum", "فحص تسجيلات الإشارات الراديوية", "Inspect recorded radio signals", "https://github.com/miek/inspectrum"),
        ("readsb / tar1090", "استقبال ADS-B وعرض الطائرات محلياً", "Receive ADS-B and show aircraft locally", "https://github.com/wiedehopf/tar1090"),
        ("WSJT-X", "اتصالات هواة ضعيفة الإشارة (FT8)", "Weak-signal amateur modes (FT8)", "https://wsjt.sourceforge.io/wsjtx.html"),
        ("Direwolf", "مودم APRS برمجي", "Software APRS TNC", "https://github.com/wb2osz/direwolf"),
        ("SatDump", "استقبال صور أقمار الطقس", "Weather-satellite image decoding", "https://github.com/SatDump/SatDump"),
        ("multimon-ng", "فك ترميز أنظمة بيجر ورسائل رقمية عامة", "Decode pager and other open digital modes", "https://github.com/EliasOenal/multimon-ng"),
        ("Proxmark3", "بحث أمني في RFID/NFC (على أجهزتك)", "RFID/NFC security research (on your own devices)", "https://github.com/RfidResearchGroup/proxmark3"),
    ]),
    "harden": ("🔧", "التحصين وإدارة الثغرات", "Hardening & vulnerability management", [
        ("Lynis", "تدقيق أمني وتحصين لأنظمة لينكس/يونكس", "Security auditing for Linux/Unix", "https://cisofy.com/lynis/"),
        ("OpenSCAP", "فحص الامتثال والتحصين الآلي", "Automated compliance & hardening scans", "https://www.open-scap.org"),
        ("CIS Benchmarks", "معايير تحصين معتمدة لمئات المنتجات", "Consensus hardening baselines", "https://www.cisecurity.org/cis-benchmarks"),
        ("Greenbone / OpenVAS", "ماسح ثغرات مفتوح المصدر", "Open-source vulnerability scanner", "https://www.greenbone.net"),
        ("Trivy", "فحص الحاويات والتبعيات وIaC", "Scanner for containers, dependencies and IaC", "https://trivy.dev"),
        ("Grype / Syft", "فحص الثغرات وإنشاء SBOM", "Vulnerability scanning and SBOM generation", "https://github.com/anchore/grype"),
        ("OSV-Scanner", "فحص التبعيات مقابل قاعدة OSV", "Dependency scanning against OSV", "https://google.github.io/osv-scanner/"),
    ]),
    "devsec": ("🧑‍💻", "الأمن في التطوير DevSecOps", "DevSecOps", [
        ("Semgrep", "تحليل ساكن للشيفرة بقواعد قابلة للتخصيص", "Static analysis with custom rules", "https://semgrep.dev"),
        ("CodeQL", "تحليل شيفرة بالاستعلامات (مجاني للمشاريع المفتوحة)", "Query-based code analysis", "https://codeql.github.com"),
        ("Bandit", "فحص أمان شيفرة بايثون", "Security linter for Python", "https://bandit.readthedocs.io"),
        ("Gitleaks", "اكتشاف الأسرار المسرّبة في مستودعات git", "Find secrets committed to git", "https://github.com/gitleaks/gitleaks"),
        ("TruffleHog", "بحث عن أسرار وتحقق من صلاحيتها", "Find and verify leaked secrets", "https://trufflesecurity.com/trufflehog"),
        ("Checkov", "فحص أمان Terraform وKubernetes وغيرها", "IaC security scanning", "https://www.checkov.io"),
        ("OWASP Dependency-Check", "كشف تبعيات بها ثغرات معروفة", "Detect dependencies with known vulnerabilities", "https://owasp.org/www-project-dependency-check/"),
    ]),
    "privacy": ("🔐", "الخصوصية وكلمات المرور والتشفير", "Privacy, passwords & encryption", [
        ("Bitwarden", "مدير كلمات مرور مفتوح المصدر", "Open-source password manager", "https://bitwarden.com"),
        ("KeePassXC", "مدير كلمات مرور محلي بلا سحابة", "Offline password manager", "https://keepassxc.org"),
        ("Aegis Authenticator", "مصادقة ثنائية مفتوحة المصدر لأندرويد", "Open-source 2FA app for Android", "https://getaegis.app"),
        ("VeraCrypt", "تشفير الأقراص والحاويات", "Disk and container encryption", "https://www.veracrypt.fr"),
        ("age", "أداة تشفير ملفات بسيطة وحديثة", "Simple modern file encryption", "https://github.com/FiloSottile/age"),
        ("GnuPG", "التوقيع والتشفير بـ OpenPGP", "OpenPGP signing & encryption", "https://gnupg.org"),
        ("Cryptomator", "تشفير ملفات السحابة", "Client-side cloud encryption", "https://cryptomator.org"),
        ("Signal", "مراسلة مشفّرة طرفاً لطرف", "End-to-end encrypted messaging", "https://signal.org"),
        ("Tor Browser", "تصفح يخفي موقعك", "Browsing that hides your location", "https://www.torproject.org"),
    ]),
    "learn": ("🎓", "التعلّم والتدريب", "Learning & training", [
        ("TryHackMe", "مسارات تعليمية تفاعلية للمبتدئين", "Guided beginner-friendly paths", "https://tryhackme.com"),
        ("Hack The Box", "مختبرات متقدمة وتحديات", "Advanced labs and challenges", "https://www.hackthebox.com"),
        ("PortSwigger Web Security Academy", "تعلّم أمن الويب مجاناً", "Free web-security training", "https://portswigger.net/web-security"),
        ("CyberDefenders", "تحديات للمدافعين (Blue Team)", "Blue-team challenges", "https://cyberdefenders.org"),
        ("Blue Team Labs Online", "مختبرات للمحللين والمستجيبين", "Labs for analysts and responders", "https://blueteamlabs.online"),
        ("OWASP", "مشاريع ومعايير مجانية لأمن التطبيقات", "Free projects and standards for application security", "https://owasp.org"),
    ]),
}


def categories() -> list:
    return [(k, v[0], v[1], v[2], len(v[3])) for k, v in CATALOG.items()]


def category_html(key: str, lang: str) -> str:
    icon, ar, en, tools = CATALOG[key]
    e = html.escape
    lines = [f"{icon} <b>{e(ar if lang == 'ar' else en)}</b>"]
    body = [f'<a href="{e(url, quote=True)}">{e(name)}</a> — {e(a if lang == "ar" else n)}' for name, a, n, url in tools]
    lines.append("<blockquote expandable>" + "\n".join(body) + "</blockquote>")
    return "\n".join(lines)


def search(query: str, limit: int = 8) -> list:
    """Offline search over names, notes and category titles. Returns [(category_key, tool_tuple)]."""
    words = [w for w in query.lower().split() if len(w) > 1]
    if not words:
        return []
    scored = []
    for key, (icon, ar, en, tools) in CATALOG.items():
        for t in tools:
            hay = f"{t[0]} {t[1]} {t[2]} {ar} {en} {key}".lower()
            score = sum(3 if w in t[0].lower() else 1 for w in words if w in hay)
            if score:
                scored.append((score, key, t))
    scored.sort(key=lambda x: -x[0])
    return [(k, t) for _, k, t in scored[:limit]]


def names_for_prompt() -> str:
    """Compact list handed to the model so recommendations come from known tools."""
    return "\n".join(f"{CATALOG[k][2]}: " + ", ".join(t[0] for t in CATALOG[k][3]) for k in CATALOG)
