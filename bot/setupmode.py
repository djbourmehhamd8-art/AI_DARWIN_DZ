"""Setup mode: what to do on a host when the essential settings are missing.

Instead of crashing (and being restarted in a loop by the hosting platform) the process stays up and serves a page that says
exactly which setting is missing. The hosting panel restarts the app by itself when the environment is saved.
"""
from __future__ import annotations

import html
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

log = logging.getLogger("bot.setup")

PAGE = """<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>DARWIN DZ - الإعداد</title>
<style>body{{font:16px/1.7 system-ui,Tahoma,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:24px}}
.c{{max-width:640px;margin:6vh auto;background:#161b22;border:1px solid #30363d;border-radius:12px;padding:22px}}
code{{background:#0d1117;padding:2px 8px;border-radius:6px;direction:ltr;display:inline-block}}li{{margin:6px 0}}.b{{color:#f85149}}</style></head>
<body><div class="c"><h1>🛡 DARWIN DZ</h1><p class="b">البوت لم يبدأ لأن الإعدادات الأساسية ناقصة:</p><ul>{items}</ul>
<p>افتح صفحة البوت في الاستضافة ← <b>Environment</b> وأضف المتغيرات الناقصة، واحفظ. سيُعاد التشغيل تلقائياً.</p>
<h3>الأساسي فقط (3 متغيرات)</h3><ul>
<li><code>TELEGRAM_TOKEN</code> توكن البوت من @BotFather</li>
<li><code>API_KEY</code> مفتاح مزوّد الذكاء الاصطناعي</li>
<li><code>ADMIN_IDS</code> معرّفك الرقمي (أرسل /id للبوت بعد تشغيله) - اختياري في أول مرة</li></ul></div></body></html>"""


def serve(host: str, port: int, problems: list, stop: threading.Event) -> None:
    """Block until `stop` is set, serving the setup page on host:port. Never raises on a busy port."""
    body = PAGE.format(items="".join(f"<li>{html.escape(p)}</li>" for p in problems)).encode("utf-8")

    class H(BaseHTTPRequestHandler):
        server_version = "DZ"
        sys_version = ""

        def log_message(self, *a):
            pass

        def do_GET(self):
            ok = self.path == "/healthz"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain" if ok else "text/html; charset=utf-8")
            data = b"ok" if ok else body
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        do_HEAD = do_GET

    try:
        srv = ThreadingHTTPServer((host, port), H)
    except OSError as e:
        log.error("setup page could not start on %s:%s: %s", host, port, e)
        stop.wait()
        return
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True, name="setup-page").start()
    log.info("Setup mode: serving the missing-settings page on http://%s:%s", host, port)
    stop.wait()
    srv.shutdown()
    srv.server_close()
