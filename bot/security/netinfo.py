"""Offline IP / CIDR classification (stdlib `ipaddress` only)."""
from __future__ import annotations

import ipaddress

from .ioc import refang

NOTES = {
    "169.254.169.254": ("عنوان خدمة بيانات السحابة (metadata): هدف شائع لهجمات SSRF، احجبه من التطبيقات.",
                        "Cloud metadata service: classic SSRF target, block it from application egress."),
}
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def analyze(text: str) -> dict:
    s = refang(text.strip().split()[0]) if text.strip() else ""
    try:
        if "/" in s:
            net = ipaddress.ip_network(s, strict=False)
            first = net.network_address
            return {"ok": True, "kind": "net", "net": net, "first": first,
                    "last": net.broadcast_address if net.version == 4 else net[-1],
                    "count": net.num_addresses, "private": net.is_private, "ver": net.version}
        ip = ipaddress.ip_address(s)
    except ValueError:
        return {"ok": False}
    flags = [n for n in ("is_private", "is_loopback", "is_link_local", "is_multicast", "is_reserved",
                         "is_unspecified", "is_global") if getattr(ip, n)]
    if ip.version == 4 and ip in _CGNAT:
        flags.append("cgnat")
    return {"ok": True, "kind": "ip", "ip": ip, "flags": flags, "ver": ip.version,
            "ptr": ip.reverse_pointer, "note": NOTES.get(str(ip))}


_FLAG_TXT = {
    "is_private": ("خاص (داخلي)", "Private"), "is_loopback": ("Loopback", "Loopback"),
    "is_link_local": ("Link-local", "Link-local"), "is_multicast": ("Multicast", "Multicast"),
    "is_reserved": ("محجوز", "Reserved"), "is_unspecified": ("غير محدد", "Unspecified"),
    "is_global": ("عام قابل للتوجيه", "Global / publicly routable"),
    "cgnat": ("CGNAT (100.64/10): عنوان مشترك لدى المزوّد", "CGNAT (100.64/10): carrier-shared address"),
}


def describe(res: dict, lang: str) -> str:
    from .ioc import defang
    i = 0 if lang == "ar" else 1
    if res["kind"] == "net":
        n = res["net"]
        lines = [f"🌐 {defang(str(n))} (IPv{res['ver']})",
                 ("عدد العناوين: " if lang == "ar" else "Addresses: ") + f"{res['count']:,}",
                 f"{res['first']} → {res['last']}",
                 ("خاص" if lang == "ar" else "Private") if res["private"] else ("عام" if lang == "ar" else "Public")]
        return "\n".join(lines)
    lines = [f"🌐 {defang(str(res['ip']))} (IPv{res['ver']})"]
    lines += [f"• {_FLAG_TXT[f][i]}" for f in res["flags"] if f in _FLAG_TXT]
    lines.append(f"PTR: {res['ptr']}")
    if res["note"]:
        lines.append("⚠️ " + res["note"][i])
    return "\n".join(lines)
