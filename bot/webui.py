"""Web panel look & feel: sidebar layout, responsive navigation (CSS-only, no JavaScript), cards, tables, notices.

Appended after the base CSS in `webpanel.CSS`; only pages that render `nav()` get the app shell (body.app).
"""
from __future__ import annotations

UI_CSS = """
:root{--bg:#f3f5f9;--card:#fff;--fg:#111827;--mut:#667085;--line:#e4e7ec;--acc:#2563eb;--acc2:#1d4ed8;--soft:#eff4ff;--ok:#067647;--bad:#c01048;--warn:#b54708;--sh:0 1px 2px rgba(16,24,40,.06),0 1px 3px rgba(16,24,40,.08);--side:#0f172a;--sidefg:#cbd5e1}
@media (prefers-color-scheme:dark){:root{--bg:#0b1020;--card:#131a2d;--fg:#e8ecf4;--mut:#93a0b8;--line:#25304a;--acc:#6ea8fe;--acc2:#8ab9ff;--soft:#172447;--ok:#47cd89;--bad:#f97066;--warn:#fdb022;--sh:none;--side:#070b17;--sidefg:#b8c3d9}}
html{scroll-behavior:smooth}body{font-family:"Segoe UI","Noto Sans Arabic",Tahoma,system-ui,-apple-system,sans-serif;-webkit-text-size-adjust:100%}
:focus-visible{outline:2px solid var(--acc);outline-offset:2px}
button,input,select,textarea{transition:border-color .15s,background .15s,box-shadow .15s}
input:focus,select:focus,textarea:focus{border-color:var(--acc);box-shadow:0 0 0 3px color-mix(in srgb,var(--acc) 22%,transparent);outline:0}
button{font-weight:600}button:hover{background:var(--soft)}button.p:hover{background:var(--acc2);border-color:var(--acc2)}
button:disabled{opacity:.5;cursor:not-allowed}
body.app{display:grid;grid-template-columns:232px minmax(0,1fr);grid-template-rows:auto 1fr;grid-template-areas:"side top" "side main";min-height:100vh}
body.app>aside.side{grid-area:side;background:var(--side);color:var(--sidefg);padding:14px 10px;position:sticky;top:0;height:100vh;overflow-y:auto}
body.app>header.top{grid-area:top;position:sticky;top:0;z-index:5;display:flex;gap:10px;align-items:center;padding:10px 16px;background:color-mix(in srgb,var(--card) 92%,transparent);backdrop-filter:blur(8px);border-bottom:1px solid var(--line)}
body.app>main{grid-area:main;width:100%;max-width:1280px;margin:0 auto;padding:18px 18px 40px}
.brand{display:flex;align-items:center;gap:8px;font-weight:800;font-size:17px;color:#fff;padding:6px 10px 14px}
.brand small{display:block;font-weight:400;font-size:11px;color:var(--sidefg);opacity:.8}
.side h4{margin:16px 10px 6px;font-size:11px;letter-spacing:.04em;color:#7c8aa5;font-weight:600}
.side a{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:8px 10px;border-radius:8px;color:var(--sidefg);text-decoration:none;font-size:14px}
.side a:hover{background:rgba(255,255,255,.07);color:#fff}.side a.on{background:var(--acc);color:#fff}
.side .b{border-color:transparent;background:var(--bad);color:#fff;font-size:11px;padding:0 7px}.side .b.warn{background:var(--warn)}
.navtoggle,.burger{display:none}
.burger{cursor:pointer;font-size:20px;padding:2px 8px;border:1px solid var(--line);border-radius:8px;background:var(--card)}
.gsearch{flex:1;display:flex;gap:6px;max-width:460px}.gsearch input{flex:1;min-width:0}
.top .sp{flex:1}.top form{margin:0}
@media (max-width:860px){
 body.app{grid-template-columns:minmax(0,1fr);grid-template-areas:"top" "main"}
 body.app>aside.side{position:fixed;inset:0 0 0 auto;width:250px;height:100%;z-index:20;transform:translateX(100%);transition:transform .2s;box-shadow:-8px 0 24px rgba(0,0,0,.35)}
 [dir=rtl] body.app>aside.side{inset:0 0 0 auto}
 .navtoggle:checked~aside.side{transform:none}
 .navtoggle:checked~.scrim{display:block}
 .scrim{display:none;position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:15}
 .burger{display:inline-block}
 body.app>main{padding:12px 10px 30px}
 .top .gsearch{max-width:none}
}
.card,.stat,.wrap,details.rep{box-shadow:var(--sh)}
.stat{transition:transform .12s,border-color .12s}a.stat:hover{transform:translateY(-1px)}
.stat b{font-variant-numeric:tabular-nums}.stat em{display:block;font-style:normal;font-size:12px;margin-top:2px}
.up{color:var(--ok)}.down{color:var(--bad)}
h2{font-size:20px;margin:2px 0 14px;display:flex;align-items:center;gap:8px}
.wrap table tbody tr:nth-child(even){background:color-mix(in srgb,var(--bg) 55%,transparent)}
.wrap table tbody tr:hover{background:var(--soft)}
th{position:sticky;top:0}
.flash{display:flex;gap:8px;align-items:center;border-inline-start:4px solid var(--ok);animation:fin .25s}
.flash.warn{border-inline-start-color:var(--warn)}.flash.bad{border-inline-start-color:var(--bad);color:var(--fg)}
@keyframes fin{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:none}}
.pager{flex-wrap:wrap}.pager a{padding:4px 10px;border:1px solid var(--line);border-radius:8px;background:var(--card)}
.pager a:hover{border-color:var(--acc)}
.bulk{position:sticky;bottom:8px;display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:10px;padding:10px 12px;background:var(--card);border:1px solid var(--acc);border-radius:12px;box-shadow:0 6px 20px rgba(0,0,0,.15)}
.bulk label{font-size:13px;color:var(--mut)}
td.sel,th.sel{width:30px;text-align:center}input[type=checkbox]{width:16px;height:16px;accent-color:var(--acc)}
.empty{text-align:center;color:var(--mut);padding:26px 10px}
.kv td:first-child{color:var(--mut);width:42%}
.chart .bc:hover i{filter:brightness(1.15)}
@media print{.side,.top,.bulk,button,.tabs,.bar{display:none!important}body.app{display:block}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
"""


def sidebar(active: str, badges: dict) -> str:
    groups = (
        ("الرئيسية", (("/overview", "overview", "📊", "نظرة عامة"), ("/", "users", "👥", "المستخدمون"),
                      ("/groups", "groups", "🏘", "المجموعات"), ("/reports", "reports", "📨", "البلاغات"))),
        ("الأدوات", (("/tools", "tools", "🧰", "الأدوات"),)),
        ("الإدارة", (("/audit", "audit", "🧾", "سجل التدقيق"), ("/logs", "logs", "📜", "السجلات"), ("/system", "system", "🩺", "النظام"), ("/settings", "settings", "⚙️", "الإعدادات"))),
    )
    out = ['<div class="brand">🛡<div>DARWIN DZ<small>لوحة التحكم</small></div></div>']
    for title, items in groups:
        out.append(f"<h4>{title}</h4>")
        for href, key, ic, label in items:
            n, cls = badges.get(key, (0, ""))
            chip = f'<span class="b {cls}">{n}</span>' if n else ""
            on = key == active
            cur = ' aria-current="page"' if on else ""
            out.append(f'<a class="{"on" if on else ""}" href="{href}"{cur}><span>{ic} {label}</span>{chip}</a>')
    return "".join(out)
