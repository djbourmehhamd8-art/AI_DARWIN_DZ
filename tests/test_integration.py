"""End-to-end test with fake Telegram + fake OpenAI-compatible servers on localhost."""
import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from bot.ai_client import AIClient
from bot.config import Config
from bot.handlers import BotApp
from bot.storage import Storage
from bot.telegram import TelegramAPI

CALLS = []          # (method, params) seen by fake Telegram
QUEUE = []          # updates waiting to be delivered
SEEN = []           # message lists received by the fake AI


class FakeTelegram(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n)
        method = self.path.rsplit("/", 1)[-1]
        try:
            params = json.loads(raw)
        except ValueError:
            params = {}
        result = True
        if method == "getUpdates":
            time.sleep(0.15)
            result = [QUEUE.pop(0)] if QUEUE else []
        else:
            CALLS.append((method, params))
            if method == "getMe":
                result = {"username": "testbot"}
            elif method in ("sendMessage", "editMessageText"):
                result = {"message_id": 100 + len(CALLS)}
        body = json.dumps({"ok": True, "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FakeAI(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(n))
        if self.headers.get("Authorization") != "Bearer sk-test":
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":{"message":"bad key"}}')
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        last = req["messages"][-1]["content"]
        SEEN.append(req["messages"])
        pieces = ["w%d " % i for i in range(40)] if last == "slow" else ["Echo: ", last, " ✓"]
        delay = 0.2 if last == "slow" else 0.05
        try:
            for piece in pieces:
                chunk = {"choices": [{"delta": {"content": piece}}]}
                self.wfile.write(f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n".encode())
                self.wfile.flush()
                time.sleep(delay)
            self.wfile.write(b'data: {"usage":{"prompt_tokens":10,"completion_tokens":5},"choices":[]}\n\n')
            self.wfile.write(b"data: [DONE]\n\n")
        except (BrokenPipeError, ConnectionResetError):
            pass


def serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def msg(uid, text, update_id):
    return {"update_id": update_id, "message": {
        "message_id": update_id, "chat": {"id": uid, "type": "private"},
        "from": {"id": uid, "first_name": "Tester"}, "text": text}}


class IntegrationTest(unittest.TestCase):
    def test_flow(self):
        CALLS.clear()
        QUEUE.clear()
        tg_srv, ai_srv = serve(FakeTelegram), serve(FakeAI)
        cfg = Config(
            telegram_token="TOKEN", api_key="sk-test",
            api_base_url=f"http://127.0.0.1:{ai_srv.server_port}/v1",
            telegram_api_url=f"http://127.0.0.1:{tg_srv.server_port}",
            admin_ids=frozenset({1}), stream_interval=0.0,
        )
        db = Storage(":memory:")
        app = BotApp(cfg, TelegramAPI("TOKEN", cfg.telegram_api_url),
                     AIClient(cfg.api_base_url, cfg.api_key, cfg.model, retries=0), db)
        self.addCleanup(db.close)
        self.addCleanup(app.ai.session.close)
        self.addCleanup(app.tg.session.close)
        QUEUE.extend([
            msg(1, "hello", 1),            # admin chat
            msg(2, "hi", 2),               # not allowed -> denied
            msg(1, "/usage", 3),
            msg(1, "/stats", 4),
            msg(2, "/stats", 5),           # non-admin and denied
        ])
        th = threading.Thread(target=app.run, daemon=True)
        th.start()
        time.sleep(3)
        app.stop.set()
        th.join(timeout=10)

        texts = [p.get("text", "") for m, p in CALLS if m in ("sendMessage", "editMessageText")]
        joined = "\n".join(texts)
        self.assertIn("Echo: hello ✓", joined)          # streamed answer finalized
        self.assertIn("بوت خاص", joined)                  # user 2 sees the private-bot access screen
        self.assertIn("Messages: 1", joined.replace("الرسائل: 1", "Messages: 1"))
        self.assertIn("المستخدمون", joined)               # admin stats
        self.assertEqual(db.get_user(1)["tokens_in"], 10)
        self.assertEqual([m["role"] for m in db.get_history(1)], ["user", "assistant"])
        self.assertTrue(any(m == "setMyCommands" for m, _ in CALLS))
        tg_srv.shutdown()
        ai_srv.shutdown()
        tg_srv.server_close()
        ai_srv.server_close()


    def test_features(self):
        CALLS.clear()
        QUEUE.clear()
        SEEN.clear()
        tg_srv, ai_srv = serve(FakeTelegram), serve(FakeAI)
        cfg = Config(
            telegram_token="TOKEN", api_key="sk-test",
            api_base_url=f"http://127.0.0.1:{ai_srv.server_port}/v1",
            telegram_api_url=f"http://127.0.0.1:{tg_srv.server_port}",
            admin_ids=frozenset({1}), stream_interval=0.0, daily_limit=3, groups=True,
        )
        db = Storage(":memory:")
        app = BotApp(cfg, TelegramAPI("TOKEN", cfg.telegram_api_url),
                     AIClient(cfg.api_base_url, cfg.api_key, cfg.model, retries=0), db)
        self.addCleanup(db.close)
        self.addCleanup(app.ai.session.close)
        self.addCleanup(app.tg.session.close)
        group_msg = {"update_id": 20, "message": {
            "message_id": 20, "chat": {"id": -500, "type": "group"},
            "from": {"id": 1, "first_name": "Tester"}, "text": "@testbot ping"}}
        ignored = {"update_id": 21, "message": {
            "message_id": 21, "chat": {"id": -500, "type": "group"},
            "from": {"id": 1, "first_name": "Tester"}, "text": "no mention here"}}
        QUEUE.extend([
            msg(1, "/remember I like tea", 10),
            msg(1, "/memory", 11),
            msg(1, "/remind 1s drink water", 12),
            msg(1, "/tr hello", 13),
            group_msg, ignored,
            msg(1, "slow", 14),
        ])
        th = threading.Thread(target=app.run, daemon=True)
        th.start()
        time.sleep(2.5)
        QUEUE.append(msg(1, "/stop", 15))
        time.sleep(1.5)
        app.stop.set()
        th.join(timeout=10)

        texts = "\n".join(p.get("text", "") for m, p in CALLS if m in ("sendMessage", "editMessageText"))
        self.assertIn("1. I like tea", texts)                 # /memory listing
        self.assertIn("⏰ drink water", texts)                 # reminder delivered by scheduler
        self.assertIn("Echo: hello ✓", texts)                  # /tr one-shot
        self.assertIn("Echo: ping ✓", texts)                   # group mention (mention stripped)
        self.assertNotIn("no mention here", texts)             # ignored in groups
        self.assertTrue(any("Things the user asked you to remember" in m["content"]
                            for msgs in SEEN for m in msgs if m["role"] == "system"))
        # /stop kept the partial answer and marked it
        hist = db.get_history(1)
        self.assertEqual(hist[-2]["content"], "slow")
        self.assertTrue(hist[-1]["content"].startswith("w0 w1"))
        self.assertLess(len(hist[-1]["content"]), len("w0 " * 40))
        self.assertIn("⏹", texts)
        # /tr is not stored in history
        self.assertNotIn("hello", "".join(m["content"] for m in hist))
        tg_srv.shutdown()
        ai_srv.shutdown()
        tg_srv.server_close()
        ai_srv.server_close()

    def test_security_flow(self):
        CALLS.clear()
        QUEUE.clear()
        SEEN.clear()
        tg_srv, ai_srv = serve(FakeTelegram), serve(FakeAI)
        cfg = Config(
            telegram_token="TOKEN", api_key="sk-test",
            api_base_url=f"http://127.0.0.1:{ai_srv.server_port}/v1",
            telegram_api_url=f"http://127.0.0.1:{tg_srv.server_port}",
            admin_ids=frozenset({1}), stream_interval=0.0, hibp=False,
        )
        db = Storage(":memory:")
        app = BotApp(cfg, TelegramAPI("TOKEN", cfg.telegram_api_url),
                     AIClient(cfg.api_base_url, cfg.api_key, cfg.model, retries=0), db)
        self.addCleanup(db.close)
        self.addCleanup(app.ai.session.close)
        self.addCleanup(app.tg.session.close)
        QUEUE.extend([
            msg(1, "who are you? my key is AKIAABCDEFGHIJKLMNOP", 30),
            msg(1, "/url http://paypa1-login.tk/verify", 31),
            msg(1, "/pass Password1", 32),
            msg(1, "/hash 5f4dcc3b5aa765d61d8327deb882cf99", 33),
            msg(1, "/cve CVE-2024-3094", 34),
            msg(1, "/audit", 35),
            msg(2, "/start", 36),
        ])
        th = threading.Thread(target=app.run, daemon=True)
        th.start()
        time.sleep(3.5)
        app.stop.set()
        th.join(timeout=10)
        texts = "\n".join(p.get("text", "") for m, p in CALLS if m in ("sendMessage", "editMessageText"))
        # identity prompt reaches the model, secrets never do
        systems = [m["content"] for msgs in SEEN for m in msgs if m["role"] == "system"]
        self.assertTrue(any("You are DARWIN DZ" in s for s in systems))
        sent = json.dumps(SEEN)
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", sent)
        self.assertIn("REDACTED:aws_key", sent)
        self.assertIn("🚨", texts)                                  # user warned
        self.assertIn("ينتحل اسم علامة", texts)   # /url finding (Arabic default)
        self.assertIn("🔐", texts)                                  # /pass result
        self.assertIn("MD5", texts)                                 # /hash identification
        self.assertIn("CVE-2024-3094", sent)                        # /cve prompt reached the model
        self.assertIn("secret_masked", texts)                       # admin /audit shows the event
        self.assertTrue(any(m == "deleteMessage" for m, _ in CALLS))  # password / secret messages removed
        self.assertNotIn("Password1", "".join(m["content"] for m in db.get_history(1)))
        self.assertIn("denied", texts + "".join(r["action"] for r in db.list_audit()))
        tg_srv.shutdown()
        ai_srv.shutdown()
        tg_srv.server_close()
        ai_srv.server_close()


if __name__ == "__main__":
    unittest.main()
