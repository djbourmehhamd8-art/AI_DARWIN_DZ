"""Verified CVE facts from NVD (+ CISA KEV flags that NVD carries) and FIRST EPSS — used to GROUND the AI so it never
invents scores, dates or exploitation status. All hosts are fixed; results are cached for a few hours."""
from __future__ import annotations

import re
import time

import requests

CVE_ID = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
TTL = 6 * 3600
_cache: dict = {}
UA = "DarwinBot/4.2 (defensive security assistant)"


def find_ids(text: str, limit: int = 3) -> list:
    seen, out = set(), []
    for m in CVE_ID.findall(text or ""):
        c = m.upper()
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out[:limit]


def _best_cvss(metrics: dict):
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if arr:
            d = arr[0].get("cvssData", {})
            return {"version": d.get("version", ""), "score": d.get("baseScore"), "severity": d.get("baseSeverity") or arr[0].get("baseSeverity", ""),
                    "vector": d.get("vectorString", "")}
    return None


def fetch(cve: str, http=requests, api_key: str = "", timeout: float = 10, now=None) -> dict:
    """Return facts dict or {"ok": False, "error": ...}. Never raises."""
    cve = cve.upper()
    clock = (now or time.time)()
    hit = _cache.get(cve)
    if hit and clock - hit[0] < TTL:
        return hit[1]
    headers = {"User-Agent": UA}
    if api_key:
        headers["apiKey"] = api_key
    try:
        r = http.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"cveId": cve}, headers=headers, timeout=timeout)
        if r.status_code == 404 or (r.status_code == 200 and not r.json().get("vulnerabilities")):
            res = {"ok": False, "error": "not_found", "id": cve}
            _cache[cve] = (clock, res)
            return res
        if r.status_code != 200:
            return {"ok": False, "error": f"NVD HTTP {r.status_code}", "id": cve}
        c = r.json()["vulnerabilities"][0]["cve"]
    except Exception as e:                                           # noqa: BLE001
        return {"ok": False, "error": type(e).__name__, "id": cve}
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    cwes = sorted({d["value"] for w in c.get("weaknesses", []) for d in w.get("description", []) if d.get("value", "").startswith("CWE-")})
    refs = [x.get("url", "") for x in c.get("references", []) if str(x.get("url", "")).startswith("https://")][:4]
    facts = {"ok": True, "id": cve, "description": desc[:900], "cvss": _best_cvss(c.get("metrics", {})),
             "published": (c.get("published") or "")[:10], "modified": (c.get("lastModified") or "")[:10],
             "status": c.get("vulnStatus", ""), "cwes": cwes[:4], "refs": refs,
             "kev": bool(c.get("cisaExploitAdd")), "kev_added": c.get("cisaExploitAdd", ""), "kev_due": c.get("cisaActionDue", ""),
             "kev_name": c.get("cisaVulnerabilityName", ""), "epss": None, "epss_pct": None}
    try:
        e = http.get("https://api.first.org/data/v1/epss", params={"cve": cve}, headers={"User-Agent": UA}, timeout=6)
        row = (e.json().get("data") or [None])[0] if e.status_code == 200 else None
        if row:
            facts["epss"], facts["epss_pct"] = float(row["epss"]), float(row["percentile"])
    except Exception:                                                # noqa: BLE001 - EPSS is optional
        pass
    _cache[cve] = (clock, facts)
    return facts


def prompt_block(facts_list: list, today: str) -> str:
    """Text for the model. Marked as verified data, with an instruction not to contradict or extend it with guesses."""
    rows = []
    for f in facts_list:
        if not f.get("ok"):
            rows.append(f"{f['id']}: NOT FOUND in NVD ({f.get('error')}). Do not describe it as if it existed; say it could not be verified.")
            continue
        cv = f["cvss"]
        rows.append(
            f"{f['id']} (NVD status {f['status']}; published {f['published']}; modified {f['modified']})\n"
            f"  CVSS: {('v' + str(cv['version']) + ' ' + str(cv['score']) + ' ' + str(cv['severity']) + ' ' + cv['vector']) if cv else 'not scored yet'}\n"
            f"  CISA KEV (known exploited): {'YES, added ' + f['kev_added'] + ', federal due date ' + f['kev_due'] if f['kev'] else 'not listed'}\n"
            f"  EPSS: {('%.1f%% probability of exploitation in 30 days (percentile %.0f%%)' % (f['epss'] * 100, f['epss_pct'] * 100)) if f['epss'] is not None else 'unavailable'}\n"
            f"  CWE: {', '.join(f['cwes']) or 'n/a'}\n  Description: {f['description']}")
    return (f"VERIFIED CVE DATA (fetched just now, {today}, from NVD/CISA/FIRST). Treat these numbers and dates as ground truth: do "
            "not contradict them, and label anything you add from memory (affected versions, patches, detection) as unverified.\n" + "\n".join(rows))


def card_html(f: dict, lang: str, esc) -> str:
    """Compact card shown to the user (HTML)."""
    ar = lang == "ar"
    if not f.get("ok"):
        return f"🔎 <b>{esc(f['id'])}</b>\n" + ("لم أجد هذا المعرّف في NVD (قد يكون غير صحيح أو حديثاً جداً)." if ar and f.get("error") == "not_found"
                                              else "Not found in NVD (it may be wrong or very new)." if f.get("error") == "not_found"
                                              else f"({esc(f.get('error'))})")
    cv = f["cvss"]
    sev = (cv or {}).get("severity", "").upper()
    dot = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
    lines = [f"{dot} <b>{esc(f['id'])}</b>" + (f" — CVSS {cv['score']} {esc(sev)}" if cv else (" — لم تُقيَّم بعد" if ar else " — not scored yet"))]
    q = [esc(f["description"][:420] + ("…" if len(f["description"]) > 420 else ""))]
    if cv and cv.get("vector"):
        q.append(f"<code>{esc(cv['vector'])}</code>")
    q.append(("📅 نُشرت " if ar else "📅 Published ") + esc(f["published"]) + (" · " + ("عُدّلت " if ar else "modified ") + esc(f["modified"])))
    if f["kev"]:
        q.append("🚨 " + (f"<b>مستغَلّة فعلياً (CISA KEV)</b> — أُضيفت {esc(f['kev_added'])}، الموعد الاتحادي {esc(f['kev_due'])}" if ar
                          else f"<b>Actively exploited (CISA KEV)</b> — added {esc(f['kev_added'])}, federal due {esc(f['kev_due'])}"))
    else:
        q.append("🟢 " + ("غير مدرجة في CISA KEV" if ar else "Not in CISA KEV"))
    if f["epss"] is not None:
        q.append(f"📈 EPSS {f['epss'] * 100:.1f}% ({'المئين' if ar else 'percentile'} {f['epss_pct'] * 100:.0f})")
    if f["cwes"]:
        q.append("🧩 " + esc(", ".join(f["cwes"])))
    lines.append("<blockquote>" + "\n".join(q) + "</blockquote>")
    if f["refs"]:
        lines.append(("🔗 " + ("مراجع" if ar else "References") + ": ") + " · ".join(f'<a href="{esc(u)}">{i}</a>' for i, u in enumerate(f["refs"], 1)))
    lines.append("<i>NVD · CISA · FIRST</i>")
    return "\n".join(lines)
