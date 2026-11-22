"""Well-known TCP/UDP ports: what they are and what to check. Local lookup, no network."""
from __future__ import annotations

import re

# port: (service, risk, Arabic note, English note)
PORTS = {
    20: ("FTP data", "high", "نقل غير مشفّر", "unencrypted transfer"),
    21: ("FTP", "high", "غير مشفّر؛ عطّل الدخول المجهول واستبدله بـSFTP", "cleartext; disable anonymous login, prefer SFTP"),
    22: ("SSH", "med", "فعّل المفاتيح وعطّل كلمة المرور وroot، وقيّد المصدر", "use keys, disable password/root login, restrict sources"),
    23: ("Telnet", "high", "غير مشفّر تماماً؛ عطّله واستخدم SSH", "fully cleartext; disable, use SSH"),
    25: ("SMTP", "med", "منع الترحيل المفتوح وفعّل SPF/DKIM/DMARC", "block open relay; enable SPF/DKIM/DMARC"),
    53: ("DNS", "med", "عطّل نقل المنطقة AXFR والتكبير (amplification)", "disable AXFR and open recursion"),
    67: ("DHCP", "low", "راقب خوادم DHCP المارقة", "watch for rogue DHCP servers"),
    69: ("TFTP", "high", "بلا مصادقة؛ لا تعرّضه", "no authentication; do not expose"),
    80: ("HTTP", "med", "حوّل إلى HTTPS وفعّل HSTS", "redirect to HTTPS, enable HSTS"),
    88: ("Kerberos", "med", "هدف شائع (Kerberoasting)؛ راقب الطلبات الشاذة", "common target (Kerberoasting); monitor"),
    110: ("POP3", "med", "استخدم 995 المشفّر", "use encrypted 995"),
    111: ("RPCbind", "high", "لا تعرّضه للإنترنت", "do not expose to the internet"),
    123: ("NTP", "low", "عطّل أمر monlist لمنع التكبير", "disable monlist to prevent amplification"),
    135: ("MS RPC", "high", "لا تعرّضه خارج الشبكة الداخلية", "never expose outside the LAN"),
    137: ("NetBIOS-NS", "high", "عطّل NetBIOS إن لم يلزم", "disable NetBIOS if unneeded"),
    139: ("NetBIOS-SSN", "high", "عطّله وأغلقه على الحدود", "disable and block at the perimeter"),
    143: ("IMAP", "med", "استخدم 993 المشفّر", "use encrypted 993"),
    161: ("SNMP", "high", "غيّر community الافتراضي واستخدم v3", "change default community, use v3"),
    389: ("LDAP", "med", "استخدم LDAPS/StartTLS ومنع الربط المجهول", "use LDAPS/StartTLS, block anonymous bind"),
    443: ("HTTPS", "low", "حدّث TLS وعطّل البروتوكولات القديمة", "keep TLS modern, disable legacy protocols"),
    445: ("SMB", "high", "لا تعرّضه للإنترنت؛ عطّل SMBv1 (EternalBlue)", "never expose; disable SMBv1 (EternalBlue)"),
    465: ("SMTPS", "low", "بريد مشفّر", "encrypted mail submission"),
    514: ("Syslog", "med", "UDP بلا مصادقة؛ قيّد المصدر", "UDP, unauthenticated; restrict sources"),
    587: ("SMTP submission", "low", "اشترط المصادقة وSTARTTLS", "require auth and STARTTLS"),
    636: ("LDAPS", "low", "LDAP مشفّر", "encrypted LDAP"),
    873: ("rsync", "med", "اشترط المصادقة", "require authentication"),
    993: ("IMAPS", "low", "IMAP مشفّر", "encrypted IMAP"),
    995: ("POP3S", "low", "POP3 مشفّر", "encrypted POP3"),
    1433: ("MS SQL", "high", "لا تعرّضه؛ قيّد المصدر وعطّل sa", "do not expose; restrict sources, disable sa"),
    1521: ("Oracle DB", "high", "لا تعرّضه للإنترنت", "do not expose to the internet"),
    2049: ("NFS", "high", "قيّد التصدير بعناوين محددة", "restrict exports to specific hosts"),
    2375: ("Docker API", "high", "بلا مصادقة = تحكم كامل بالمضيف! أغلقه", "unauthenticated = host takeover! close it"),
    2376: ("Docker TLS", "med", "تأكد من مصادقة الشهادات المتبادلة", "ensure mutual TLS auth"),
    3306: ("MySQL/MariaDB", "high", "اربطه بـlocalhost أو شبكة خاصة", "bind to localhost/private network"),
    3389: ("RDP", "high", "هدف فدية رئيسي؛ خلف VPN مع MFA وNLA", "top ransomware entry; VPN + MFA + NLA"),
    5432: ("PostgreSQL", "high", "قيّد pg_hba.conf ولا تعرّضه", "restrict pg_hba.conf, do not expose"),
    5601: ("Kibana", "med", "اشترط المصادقة", "require authentication"),
    5900: ("VNC", "high", "ضعيف المصادقة؛ مرّره عبر SSH/VPN", "weak auth; tunnel via SSH/VPN"),
    5985: ("WinRM HTTP", "med", "قيّد المصدر واستخدم 5986", "restrict sources, prefer 5986"),
    5986: ("WinRM HTTPS", "med", "قيّد المصدر وراقب الاستخدام", "restrict sources and monitor"),
    6379: ("Redis", "high", "بلا مصادقة افتراضياً؛ اربطه بـlocalhost وفعّل requirepass", "no auth by default; bind localhost, set requirepass"),
    8080: ("HTTP alt", "med", "غالباً لوحات إدارة؛ تحقق منها", "often admin panels; verify"),
    8443: ("HTTPS alt", "med", "غالباً لوحات إدارة؛ تحقق منها", "often admin panels; verify"),
    9200: ("Elasticsearch", "high", "بلا مصادقة افتراضياً؛ لا تعرّضه", "no auth by default; do not expose"),
    11211: ("Memcached", "high", "تكبير DDoS؛ اربطه بـlocalhost", "DDoS amplification; bind localhost"),
    27017: ("MongoDB", "high", "فعّل المصادقة ولا تعرّضه", "enable auth, do not expose"),
}
RISK = {"low": "🟢", "med": "🟡", "high": "🔴"}


def lookup(query: str) -> list:
    """Numbers (comma/space/range separated) or a service name fragment -> list of (port, entry)."""
    q = query.strip().lower()
    out, seen = [], set()
    for tok in re.split(r"[,\s]+", q):
        if not tok:
            continue
        m = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", tok)
        if m:
            lo = int(m.group(1))
            hi = int(m.group(2) or lo)
            for p in range(lo, min(hi, lo + 200) + 1):
                if p in PORTS and p not in seen:
                    seen.add(p)
                    out.append((p, PORTS[p]))
        else:
            for p, e in PORTS.items():
                if tok in e[0].lower() and p not in seen:
                    seen.add(p)
                    out.append((p, e))
    return out[:30]


def describe(items: list, lang: str) -> list:
    """HTML lines."""
    import html
    lines = []
    for p, (svc, risk, ar, en) in items:
        lines.append(f"{RISK[risk]} <b>{p}</b> · {html.escape(svc)}\n{'\u2003'}{html.escape(ar if lang == 'ar' else en)}")
    return lines
