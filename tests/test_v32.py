"""Tests for v3.2: structured formatting, answer buttons, reply style, tidy prompts, hardening."""
import sqlite3
import tempfile
import os
import unittest

from bot import formatting as fm
from bot.ai_client import AIClient, APIError
from bot.config import Config
from bot.handlers import BotApp
from bot.storage import Storage
from bot.telegram import TelegramAPI
from tests import test_integration as ti
from tests.test_ui import cb, message


class FormatterTests(unittest.TestCase):
    def test_lists_quotes_links_emphasis(self):
        h = fm.to_html("- a\n  - b\n1. x\n> q\n[t](https://e.com?a=1&b=2) *i* **b** ~~s~~ snake_case_name 2*3*4")
        self.assertIn("• a", h)
        self.assertIn("◦ b", h)
        self.assertIn("<blockquote>q</blockquote>", h)
        self.assertIn('<a href="https://e.com?a=1&amp;b=2">t</a>', h)
        self.assertIn("<i>i</i>", h)
        self.assertIn("<s>s</s>", h)
        self.assertIn("snake_case_name", h)           # underscores inside words are not italics
        self.assertIn("2*3*4", h)

    def test_unsafe_link_scheme_not_linked(self):
        h = fm.to_html("[x](javascript:alert(1))")
        self.assertNotIn("<a ", h)

    def test_tables_become_mobile_friendly_lists(self):
        two = fm.to_html("| k | v |\n|---|---|\n| a | b |")
        self.assertIn("• <b>a</b> — b", two)
        self.assertNotIn("|", two)
        three = fm.to_html("| tool | use | risk |\n|---|---|---|\n| nmap | scan | low |")
        self.assertIn("<b>nmap</b>", three)
        self.assertIn("use: scan", three)

    def test_crossed_emphasis_never_produces_invalid_html(self):
        h = fm.to_html("**a *b** c*")
        self.assertTrue(fm._balanced(h))

    def test_unclosed_fence_is_closed(self):
        h = fm.to_html("text\n```python\nprint(1)\n")
        self.assertIn("<pre><code", h)
        self.assertTrue(fm._balanced(h))

    def test_split_keeps_code_fences_valid(self):
        text = "intro\n```python\n" + "x = 1\n" * 1500 + "```\nend " + "word " * 800
        chunks = fm.split_md(text, 3200)
        self.assertGreater(len(chunks), 2)
        for c in chunks:
            self.assertLessEqual(len(c), 3200)
            self.assertEqual(c.count("```") % 2, 0, "every chunk must close its own code block")
        for md, h in fm.render_chunks(text):
            self.assertLessEqual(fm.visible_len(h), 4000)
            self.assertTrue(fm._balanced(h))

    def test_split_is_prefix_stable_for_streaming(self):
        text = "para\n\n" * 1500
        first = fm.split_md(text[:9000])[0]
        self.assertEqual(fm.split_md(text)[0], first)


class StorageMigrationTest(unittest.TestCase):
    def test_old_database_gets_detail_column(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "old.db")
            c = sqlite3.connect(path)
            c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, first_name TEXT, lang TEXT NOT NULL "
                      "DEFAULT 'ar', persona TEXT NOT NULL DEFAULT 'default', temperature REAL NOT NULL DEFAULT 0.7, "
                      "custom_prompt TEXT NOT NULL DEFAULT '', banned INTEGER NOT NULL DEFAULT 0, allowed INTEGER NOT "
                      "NULL DEFAULT 0, created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL, msgs INTEGER NOT NULL "
                      "DEFAULT 0, tokens_in INTEGER NOT NULL DEFAULT 0, tokens_out INTEGER NOT NULL DEFAULT 0)")
            c.execute("INSERT INTO users(id, created_at, last_seen) VALUES (7, 1, 1)")
            c.commit()
            c.close()
            db = Storage(path)
            self.assertEqual(db.get_user(7)["detail"], "balanced")
            db.set_user(7, detail="concise")
            self.assertEqual(db.get_user(7)["detail"], "concise")
            db.close()


class ClientHardeningTest(unittest.TestCase):
    def test_stream_without_terminal_event_is_rejected(self):
        class R:
            encoding = None
            def iter_lines(self, chunk_size=1):
                yield b'data: {"choices":[{"delta":{"content":"partial"}}]}'
            def close(self):
                self.closed = True
        response = R()
        with self.assertRaisesRegex(APIError, "incomplete stream"):
            AIClient._read(response, True, None)
        self.assertTrue(response.closed)

    def test_malformed_json_reply_is_an_api_error(self):
        class R:
            def __init__(self):
                self.closed = False
            def json(self):
                return {"unexpected": True}
            def close(self):
                self.closed = True
        response = R()
        with self.assertRaises(APIError):
            AIClient._read(response, False, None)
        self.assertTrue(response.closed)

    def test_non_stream_reply_closes_response(self):
        class R:
            closed = False
            def json(self):
                return {"choices": [{"message": {"content": "ok"}}], "usage": {"total_tokens": 2}}
            def close(self):
                self.closed = True
        response = R()
        self.assertEqual(AIClient._read(response, False, None), ("ok", {"total_tokens": 2}))
        self.assertTrue(response.closed)


class AppFlowTest(unittest.TestCase):
    def setUp(self):
        ti.CALLS.clear()
        ti.SEEN.clear()
        self.tg_srv, self.ai_srv = ti.serve(ti.FakeTelegram), ti.serve(ti.FakeAI)
        cfg = Config(telegram_token="TOKEN", api_key="sk-test",
                     api_base_url=f"http://127.0.0.1:{self.ai_srv.server_port}/v1",
                     telegram_api_url=f"http://127.0.0.1:{self.tg_srv.server_port}",
                     admin_ids=frozenset({1}), stream_interval=0.0, hibp=False)
        self.db = Storage(":memory:")
        self.app = BotApp(cfg, TelegramAPI("TOKEN", cfg.telegram_api_url),
                          AIClient(cfg.api_base_url, cfg.api_key, cfg.model, retries=0), self.db)
        self.app.bot_username = "testbot"

    def tearDown(self):
        self.app.tg.session.close()
        self.app.ai.session.close()
        self.db.close()
        self.tg_srv.shutdown()
        self.ai_srv.shutdown()
        self.tg_srv.server_close()
        self.ai_srv.server_close()

    def calls(self, *methods):
        return [p for m, p in ti.CALLS if m in methods]

    def buttons(self):
        out = []
        for p in self.calls("sendMessage", "editMessageText"):
            for row in (p.get("reply_markup") or {}).get("inline_keyboard", []):
                out += [b["callback_data"] for b in row]
        return out

    def test_answer_has_followup_buttons_and_html(self):
        self.app.on_message(message(1, "hello"))
        last = self.calls("sendMessage", "editMessageText")[-1]
        self.assertEqual(last.get("parse_mode"), "HTML")
        data = [b["callback_data"] for row in last["reply_markup"]["inline_keyboard"] for b in row]
        for want in ("act:retry", "ans:more", "ans:short", "ans:tr", "m:main"):
            self.assertIn(want, data)
        self.assertNotIn("act:stop", data)             # the stop button is gone once the answer is complete

    def test_stop_button_is_shown_while_generating(self):
        self.app.on_message(message(1, "slow"))
        self.assertIn("act:stop", self.buttons())

    def test_continue_button_asks_the_model_again(self):
        self.app.on_message(message(1, "hello"))
        self.app.on_callback(cb(1, "ans:more"))
        roles = [m["role"] for m in self.db.get_history(1)]
        self.assertEqual(roles, ["user", "assistant", "user", "assistant"])

    def test_translate_button_uses_last_answer_without_polluting_history(self):
        self.app.on_message(message(1, "hello"))
        n = len(self.db.get_history(1))
        self.app.on_callback(cb(1, "ans:tr"))
        self.assertEqual(len(self.db.get_history(1)), n)
        self.assertIn("Echo: hello", ti.SEEN[-1][-1]["content"])

    def test_reply_style_changes_the_prompt(self):
        self.app.on_callback(cb(1, "detail:concise"))
        self.assertEqual(self.db.get_user(1)["detail"], "concise")
        self.app.on_message(message(1, "hi"))
        system = ti.SEEN[-1][0]["content"]
        self.assertIn("REPLY STYLE: concise", system)
        self.assertLess(system.index("REPLY STYLE"), system.index("FINAL OPERATING RULES"))   # safety rules stay last

    def test_prompt_message_is_edited_in_place_then_removed(self):
        self.app.on_callback(cb(1, "t:url", mid=500))
        edits = self.calls("editMessageText")
        self.assertTrue(any(p.get("message_id") == 500 for p in edits))        # the menu became the prompt
        self.app.on_message(message(1, "http://paypa1-login.tk/verify"))
        deleted = [p.get("message_id") for p in self.calls("deleteMessage")]
        self.assertIn(500, deleted)                                              # prompt removed after the answer

    def test_stop_button_answers_with_a_toast(self):
        self.app.on_callback(cb(1, "act:stop"))
        toasts = [p.get("text") for p in self.calls("answerCallbackQuery") if p.get("text")]
        self.assertTrue(toasts)

    def test_admin_diagnostics_button(self):
        user = self.app._user({"id": 1, "first_name": "Admin"})
        self.app.on_callback(cb(1, "adm:diag"))
        sent = [p.get("text", "") for m, p in ti.CALLS if m == "sendMessage"]
        self.assertTrue(any("SQLite: ✅ ok" in value for value in sent))

    def test_admin_status_button(self):
        self.app.on_callback(cb(1, "adm:status"))
        sent = "\n".join(p.get("text", "") for p in self.calls("sendMessage"))
        self.assertIn("DARWIN DZ v", sent)

    def test_tool_outputs_are_copyable(self):
        self.app.on_callback(cb(1, "t:hash"))
        self.app.on_message(message(1, "hello"))
        last = self.calls("sendMessage")[-1]
        self.assertIn("<code>2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824</code>", last["text"])
        self.assertEqual(last.get("parse_mode"), "HTML")

    def test_welcome_escapes_the_user_name(self):
        m = message(1, "/start")
        m["from"]["first_name"] = "<b>x"
        self.app.on_message(m)
        text = self.calls("sendMessage")[-1]["text"]
        self.assertIn("&lt;b&gt;x", text)


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------- multi-key failover
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from bot.keypool import KeyPool, parse_keys, mask

SEEN_KEYS = []
BEHAVIOUR = {}          # key -> status code to answer with (200 = ok)


class KeyedAI(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        key = self.headers.get("Authorization", "").replace("Bearer ", "")
        SEEN_KEYS.append(key)
        code = BEHAVIOUR.get(key, 200)
        if code != 200:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":{"message":"nope"}}')
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        self.wfile.write(b'data: {"choices":[{"delta":{"content":"ok from ' + key.encode() + b'"}}]}\n\n')
        self.wfile.write(b"data: [DONE]\n\n")


class KeyPoolUnit(unittest.TestCase):
    def test_parse_and_mask(self):
        self.assertEqual(parse_keys("a, b\nc;a", ["d", "b"], None), ["a", "b", "c", "d"])
        self.assertNotIn("secretsecret", mask("sk-secretsecretsecret1234"))

    def test_failover_cooldown_and_recovery(self):
        now = [0.0]
        events = []
        p = KeyPool(["k1", "k2", "k3"], clock=lambda: now[0])
        p.on_event = lambda *a: events.append(a[:2])
        self.assertEqual(p.order(), ["k1", "k2", "k3"])
        p.fail("k1", 401)
        self.assertEqual(p.order()[0], "k2")
        p.fail("k2", 429)
        self.assertEqual(p.order()[0], "k3")
        self.assertEqual(p.available(), 1)
        now[0] = 61                                    # 429 rests only a minute; 401 rests an hour
        self.assertEqual(sorted(p.order()[:2]), ["k2", "k3"])
        p.fail("k3", 0), p.fail("k2", 0)
        o = p.order()                                  # everything resting: still returns all, soonest-to-recover first
        self.assertEqual((len(o), o[-1]), (3, "k1"))
        p.ok("k2")
        self.assertIn(("up", "k2"), events)

    def test_roundrobin_rotates(self):
        p = KeyPool(["a", "b"], "roundrobin")
        self.assertNotEqual(p.order()[0], p.order()[0])


class AIFailoverTest(unittest.TestCase):
    def setUp(self):
        SEEN_KEYS.clear()
        BEHAVIOUR.clear()
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), KeyedAI)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_port}/v1"

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def client(self, keys, **kw):
        return AIClient(self.url, keys, "m", retries=0, **kw)

    def test_dead_key_falls_over_to_next_and_sticks(self):
        BEHAVIOUR.update({"k1": 401, "k2": 402})
        ai = self.client(["k1", "k2", "k3"])
        text, _ = ai.chat([{"role": "user", "content": "x"}], stream=True)
        self.assertEqual(text, "ok from k3")
        self.assertEqual(SEEN_KEYS, ["k1", "k2", "k3"])
        SEEN_KEYS.clear()
        ai.chat([{"role": "user", "content": "x"}])
        self.assertEqual(SEEN_KEYS, ["k3"])            # the dead keys are not hammered again

    def test_rate_limited_key_is_skipped(self):
        BEHAVIOUR["k1"] = 429
        text, _ = self.client(["k1", "k2"]).chat([{"role": "user", "content": "x"}], stream=False if False else True)
        self.assertEqual(text, "ok from k2")

    def test_server_error_moves_on_after_retries(self):
        BEHAVIOUR["k1"] = 503
        text, _ = self.client(["k1", "k2"]).chat([{"role": "user", "content": "x"}])
        self.assertEqual(text, "ok from k2")

    def test_bad_request_does_not_burn_other_keys(self):
        BEHAVIOUR["k1"] = 400
        with self.assertRaises(APIError) as cm:
            self.client(["k1", "k2"]).chat([{"role": "user", "content": "x"}])
        self.assertEqual(cm.exception.status, 400)
        self.assertEqual(SEEN_KEYS, ["k1"])

    def test_all_keys_dead_raises_last_error(self):
        BEHAVIOUR.update({"k1": 401, "k2": 402})
        with self.assertRaises(APIError) as cm:
            self.client(["k1", "k2"]).chat([{"role": "user", "content": "x"}])
        self.assertEqual(cm.exception.status, 402)

    def test_config_collects_keys_from_all_sources(self):
        import os
        old = dict(os.environ)
        try:
            os.environ.update({"TELEGRAM_TOKEN": "t", "API_KEY": "a", "API_KEYS": "b,c", "API_KEY_2": "d",
                               "API_KEY_10": "e"})
            self.assertEqual(Config.from_env().all_keys(), ["a", "b", "c", "d", "e"])
        finally:
            os.environ.clear()
            os.environ.update(old)


class KeysAdminTest(unittest.TestCase):
    """Focused admin-key tests; do not inherit and rerun the entire AppFlowTest suite."""

    def setUp(self):
        ti.CALLS.clear()
        ti.SEEN.clear()
        self.tg_srv, self.ai_srv = ti.serve(ti.FakeTelegram), ti.serve(ti.FakeAI)
        cfg = Config(telegram_token="TOKEN", api_key="sk-test",
                     api_base_url=f"http://127.0.0.1:{self.ai_srv.server_port}/v1",
                     telegram_api_url=f"http://127.0.0.1:{self.tg_srv.server_port}",
                     admin_ids=frozenset({1}), stream_interval=0.0, hibp=False)
        self.db = Storage(":memory:")
        self.app = BotApp(cfg, TelegramAPI("TOKEN", cfg.telegram_api_url),
                          AIClient(cfg.api_base_url, cfg.api_key, cfg.model, retries=0), self.db)
        self.app.bot_username = "testbot"

    def tearDown(self):
        self.app.tg.session.close()
        self.app.ai.session.close()
        self.db.close()
        self.tg_srv.shutdown()
        self.ai_srv.shutdown()
        self.tg_srv.server_close()
        self.ai_srv.server_close()
        self.db.close()

    def calls(self, *methods):
        return [p for m, p in ti.CALLS if m in methods]

    def buttons(self):
        out = []
        for p in self.calls("sendMessage", "editMessageText"):
            for row in (p.get("reply_markup") or {}).get("inline_keyboard", []):
                out += [b["callback_data"] for b in row]
        return out

    def test_keys_panel_masks_keys_and_is_admin_only(self):
        self.app.on_callback(cb(1, "adm:keys"))
        text = self.calls("sendMessage")[-1]["text"]
        self.assertIn("🔑", text)
        self.assertNotIn("sk-test", text)               # never shown in full
        ti.CALLS.clear()
        m = message(2, "/keys")
        self.app.cfg.__class__  # non-admin user 2 is not allowed at all
        self.app.on_message(m)
        self.assertNotIn("API keys", "".join(p.get("text", "") for p in self.calls("sendMessage")))
        self.assertNotIn("مفاتيح API", "".join(p.get("text", "") for p in self.calls("sendMessage")))

    def test_unknown_command_gets_a_hint(self):
        self.app.on_message(message(1, "/nonsense"))
        self.assertIn("m:main", self.buttons())
