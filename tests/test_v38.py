"""v3.8: audit fixes — tidy_answer safety, flag leak, button fallback, zip upload, maintenance, SQL filters."""
import io
import unittest
import zipfile
from unittest import mock

from bot import files as F
from bot import websearch as W
from bot.formatting import tidy_answer
from bot.telegram import TelegramAPI
from tests import test_integration as ti
from tests.test_ui import cb, message
from tests.test_v34 import Harness


class TidyNeverEatsContent(unittest.TestCase):
    def test_answers_that_start_with_affirmations_are_kept(self):
        for t in ("Absolutely not. Never expose port 3389 to the internet; use a VPN.",
                  "Certainly not. You should not do that at all costs.",
                  "Okay so port 22 is open. That means SSH is reachable from outside.",
                  "Absolutely. The service must be patched because the exploit is public.",
                  "تمام، المنفذ مفتوح ويجب إغلاقه الآن حتى لا يُستغل من الخارج."):
            self.assertEqual(tidy_answer(t), t)

    def test_real_pleasantries_still_removed(self):
        self.assertEqual(tidy_answer("Great question! Here is the full explanation of how TLS works."),
                         "Here is the full explanation of how TLS works.")
        self.assertEqual(tidy_answer("Sure! Here is the answer to your question about ports."),
                         "Here is the answer to your question about ports.")
        self.assertEqual(tidy_answer("Do X then Y carefully.\n\nI hope this helps!"), "Do X then Y carefully.")

    def test_instruction_lines_survive(self):
        t = "اشرح الخطوات كلها.\n\nلا تتردد في إعادة تشغيل الخدمة بعد التعديل مباشرة"
        self.assertEqual(tidy_answer(t), t)


class ButtonFallback(unittest.TestCase):
    def test_server_rejecting_style_gets_plain_buttons(self):
        api = TelegramAPI("T")
        sent = []

        def fake_call(method, timeout=30, files=None, **params):
            sent.append(params.get("reply_markup"))
            if any("style" in b for row in params["reply_markup"]["inline_keyboard"] for b in row):
                api._tl.last_error = "Bad Request: unknown field style in InlineKeyboardButton"
                return None
            return {"message_id": 1}
        markup = {"inline_keyboard": [[{"text": "🚫 x", "callback_data": "a", "style": "danger"}]]}
        with mock.patch.object(api, "call", side_effect=fake_call):
            self.assertEqual(api.send_message(1, "hi", markup), {"message_id": 1})
            self.assertFalse(api.styles_ok)
            api.send_message(1, "again", markup)
        self.assertNotIn("style", sent[-1]["inline_keyboard"][0][0])
        self.assertEqual(len(sent), 3)                                   # rejected once, then plain forever

    def test_unrelated_failure_does_not_disable_colours(self):
        api = TelegramAPI("T")

        def fake_call(method, timeout=30, files=None, **params):
            api._tl.last_error = "Bad Request: chat not found"
            return None
        markup = {"inline_keyboard": [[{"text": "x", "callback_data": "a", "style": "danger"}]]}
        with mock.patch.object(api, "call", side_effect=fake_call):
            api.send_message(1, "hi", markup)
        self.assertTrue(api.styles_ok)


class ZipReading(unittest.TestCase):
    @staticmethod
    def make(entries):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for name, data in entries:
                z.writestr(name, data)
        return buf.getvalue()

    def test_reads_text_skips_binary_and_junk_dirs(self):
        data = self.make([("app/main.py", "print('hi')"), ("img.png", b"\x89PNG\x00\x00bin"),
                          ("node_modules/x/index.js", "bad"), ("../evil.txt", "x"), ("/abs.txt", "x"),
                          ("README.md", "# hello")])
        out = F.read_zip_project(data)
        self.assertIn("--- app/main.py ---", out)
        self.assertIn("print('hi')", out)
        self.assertIn("# hello", out)
        self.assertNotIn("node_modules", out)
        self.assertNotIn("evil", out)
        self.assertNotIn("PNG", out)

    def test_limits(self):
        big = self.make([("a.txt", "x" * 200_000)])
        out = F.read_zip_project(big)
        self.assertIn("[truncated]", out)
        self.assertLess(len(out), 70_000)
        with self.assertRaises(zipfile.BadZipFile):
            F.read_zip_project(b"not a zip")
        many = self.make([(f"f{i}.txt", "a") for i in range(3001)])
        with self.assertRaises(ValueError):
            F.read_zip_project(many)

    def test_decompression_bomb_is_refused(self):
        bomb = self.make([("zeros.txt", "0" * (90 * 1024 * 1024))])      # compresses to ~90 KB, declares 90 MB
        with self.assertRaises(ValueError):
            F.read_zip_project(bomb)


class Fixes(Harness):
    __test__ = True

    def test_web_force_does_not_leak_to_next_message(self):
        self.app.ctx.web_force = True                                    # as left by an aborted /search
        with mock.patch("bot.web_files.websearch.search", return_value=[]) as s:
            self.app.on_message(message(1, "اشرح TCP"))
        self.assertFalse(s.called)

    def test_save_accepts_newline_after_name(self):
        ti.CALLS.clear()
        self.app.on_message(message(1, "/save notes.txt\nline one\nline two"))
        self.assertTrue(self.calls("sendDocument"))

    def test_save_adds_txt_when_no_extension(self):
        with mock.patch.object(self.app.tg, "send_document") as send:
            self.app.on_message(message(1, "/save notes hello"))
        self.assertEqual(send.call_args[0][1], "notes.txt")
        self.assertEqual(send.call_args[0][2], b"hello")

    def test_user_filters_in_sql(self):
        for i in range(200, 215):
            self.db.ensure_user_row(i, "ar", 0.7)
        self.db.set_user(205, banned=1)
        self.db.set_user(206, allowed=1)
        self.assertEqual([u["id"] for u in self.db.list_users(10, 0, "banned")], [205])
        self.assertEqual([u["id"] for u in self.db.list_users(10, 0, "allowed")], [206])
        with self.assertRaises(KeyError):
            self.db.list_users(10, 0, "1=1; DROP TABLE users")

    def test_zip_upload_is_read_and_sent_to_model(self):
        data = ZipReading.make([("src/app.py", "def secret_function(): pass"), ("README.md", "readme")])
        msg = message(1, "")
        msg.pop("text", None)
        msg["document"] = {"file_id": "F", "file_name": "proj.zip", "mime_type": "application/zip", "file_size": len(data)}
        msg["caption"] = "review this project"
        with mock.patch.object(self.app.tg, "get_file_bytes", return_value=data):
            self.app.on_message(msg)
        sent = ti.SEEN[-1][-1]["content"]
        self.assertIn("review this project", sent)
        self.assertIn("--- src/app.py ---", sent)

    def test_broken_zip_upload_is_refused(self):
        msg = message(1, "")
        msg.pop("text", None)
        msg["document"] = {"file_id": "F", "file_name": "x.zip", "mime_type": "application/zip", "file_size": 10}
        with mock.patch.object(self.app.tg, "get_file_bytes", return_value=b"junk"):
            self.app.on_message(msg)
        self.assertIn("📦", self.texts())


class Maintenance(Harness):
    __test__ = True

    def setUp(self):
        super().setUp()
        self.db.upsert_user(5, "u", "U")
        self.db.set_user(5, allowed=1)

    def test_toggle_blocks_users_not_admins(self):
        self.app.on_callback(cb(1, "adm:mnt"))
        self.assertTrue(self.app.maintenance)
        self.app.on_message(message(5, "hello"))
        self.assertIn("🛠", self.texts())
        before = len(ti.SEEN)
        self.app.on_message(message(5, "/help"))
        self.app.on_callback(cb(5, "m:main"))
        self.assertEqual(len(ti.SEEN), before)                           # the model was never called for the user
        self.app.on_message(message(1, "admin still works"))
        self.assertIn("Echo:", self.texts())
        self.app.on_callback(cb(1, "adm:mnt"))
        self.assertFalse(self.app.maintenance)

    def test_non_admin_cannot_toggle(self):
        self.app.on_callback(cb(5, "adm:mnt"))
        self.assertFalse(self.app.maintenance)


class PinnedFetch(unittest.TestCase):
    def test_resolver_rejects_mixed_answers(self):
        fake = [(2, 1, 6, "", ("93.184.216.34", 0)), (2, 1, 6, "", ("10.0.0.1", 0))]
        with mock.patch("bot.websearch.socket.getaddrinfo", return_value=fake):
            self.assertIsNone(W.resolve_public("evil.example"))
        with mock.patch("bot.websearch.socket.getaddrinfo", return_value=fake[:1]):
            self.assertEqual(W.resolve_public("ok.example"), "93.184.216.34")

    def test_fetch_connects_to_validated_ip(self):
        seen = {}

        class R:
            status_code = 200
            headers = {"Content-Type": "text/html"}
            encoding = "utf-8"

            def iter_content(self, n):
                yield b"<p>hello</p>"

            def close(self):
                pass

        def fake_get(url, ip, headers, timeout):
            seen["ip"] = ip
            return R()
        out = W.fetch_text("https://example.com/", get=fake_get, resolve=lambda h: "93.184.216.34")
        self.assertEqual((out, seen["ip"]), ("hello", "93.184.216.34"))


if __name__ == "__main__":
    unittest.main()
