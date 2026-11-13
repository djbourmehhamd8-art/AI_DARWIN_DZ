"""v3.6: admin panel, coloured buttons, expandable quotes, admin-in-group leak fix."""
import unittest

from bot.formatting import to_html
from bot.ui import button_style, kb
from tests import test_integration as ti
from tests.test_ui import cb, message
from tests.test_v34 import Harness


class ButtonColours(unittest.TestCase):
    def test_styles(self):
        self.assertEqual(button_style("🚫 Ban", "x"), "danger")
        self.assertEqual(button_style("✅ Send", "x"), "success")
        self.assertEqual(button_style("🏠 Menu", "m:main"), "primary")
        self.assertEqual(button_style("❌ Cancel", "x:cancel"), "danger")
        self.assertIsNone(button_style("Plain", "x"))

    def test_kb_adds_style_and_explicit_wins(self):
        m = kb([[("🚫 Ban", "a"), ("Plain", "b"), ("Plain", "c", "success")]])["inline_keyboard"][0]
        self.assertEqual(m[0]["style"], "danger")
        self.assertNotIn("style", m[1])
        self.assertEqual(m[2]["style"], "success")

    def test_env_switch_off(self):
        import os
        os.environ["BUTTON_COLORS"] = "0"
        try:
            self.assertNotIn("style", kb([[("🚫 Ban", "a")]])["inline_keyboard"][0][0])
        finally:
            del os.environ["BUTTON_COLORS"]


class Quotes(unittest.TestCase):
    def test_short_and_long_quote(self):
        self.assertIn("<blockquote>", to_html("> one\n> two"))
        self.assertIn("<blockquote expandable>", to_html("> 1\n> 2\n> 3\n> 4"))


class AdminPanel(Harness):
    __test__ = True

    def setUp(self):
        super().setUp()
        self.db.ensure_user_row(77, "ar", 0.7)
        self.db.upsert_user(77, "victim", "Victim")

    def press(self, uid, data):
        self.app.on_callback(cb(uid, data))

    def test_dashboard_has_new_buttons(self):
        self.press(1, "m:adm")
        b = self.buttons()
        for needed in ("adm:ul:0", "adm:sys", "t:adm_find", "adm:ul:0:b"):
            self.assertIn(needed, b)

    def test_non_admin_blocked(self):
        self.db.upsert_user(5, "u", "U")
        self.db.set_user(5, allowed=1)
        self.press(5, "adm:ul:0")
        self.assertNotIn("adm:u:77", self.buttons())

    def test_ban_flow_with_confirmation(self):
        self.press(1, "adm:u:77")
        self.assertIn("adm:bq:77", self.buttons())
        self.press(1, "adm:bq:77")
        self.assertEqual(self.db.get_user(77)["banned"], 0)         # still needs confirmation
        self.press(1, "adm:ban:77")
        self.assertEqual(self.db.get_user(77)["banned"], 1)
        self.assertIn("adm:ub:77", self.buttons())
        self.press(1, "adm:ub:77")
        self.assertEqual(self.db.get_user(77)["banned"], 0)
        self.assertTrue(any(a["action"] == "ban" for a in self.db.list_audit(10)))

    def test_cannot_touch_admin_or_self(self):
        self.press(1, "adm:ban:1")
        self.assertEqual(self.db.get_user(1)["banned"] if self.db.get_user(1) else 0, 0)
        self.app.on_message(message(1, "/ban 1"))
        self.assertEqual(self.db.get_user(1)["banned"] if self.db.get_user(1) else 0, 0)
        self.app.on_message(message(1, "/ban -5"))
        self.assertIsNone(self.db.get_user(-5))

    def test_find_user(self):
        self.app.on_message(message(1, "/find @victim"))
        self.assertIn("adm:bq:77", self.buttons())
        self.assertEqual(self.db.find_user("VICTIM")["id"], 77)
        self.assertIsNone(self.db.find_user("nobody"))

    def test_user_list_pagination_and_filters(self):
        for i in range(100, 112):
            self.db.ensure_user_row(i, "ar", 0.7)
        self.press(1, "adm:ul:0")
        self.assertIn("adm:ul:1", self.buttons())
        self.db.set_user(100, banned=1)
        self.press(1, "adm:ul:0:b")
        self.assertIn("adm:u:100", self.buttons(last=1))
        self.assertEqual(self.db.count_users("banned"), 1)

    def test_clear_chat(self):
        self.db.add_message(77, "user", "secret")
        self.press(1, "adm:cy:77")
        self.assertEqual(self.db.get_history(77), [])


class GroupLeakFix(Harness):
    __test__ = True

    def test_admin_commands_refused_in_groups(self):
        import dataclasses
        self.app.cfg = dataclasses.replace(self.app.cfg, groups=True)
        self.app.db.upsert_chat(-100, "G")
        self.app.db.set_chat_allowed(-100, True)           # activated, so the request reaches the admin-command guard
        msg = {"message_id": 9, "chat": {"id": -100, "type": "supergroup"},
               "from": {"id": 1, "first_name": "A"}, "text": "/backup"}
        self.app.on_message(msg)
        self.assertEqual(self.calls("sendDocument"), [])
        self.assertIn("المحادثة الخاصة", self.texts())

    def test_backup_function_never_posts_to_negative_chat(self):
        self.app.adm_backup(-100, {"id": 1, "lang": "en"}, "")
        self.assertEqual(self.calls("sendDocument"), [])

    def test_admin_buttons_dead_in_group(self):
        data = cb(1, "adm:backup")
        data["message"]["chat"] = {"id": -100, "type": "supergroup"}
        self.app.on_callback(data)
        self.assertEqual(self.calls("sendDocument"), [])


if __name__ == "__main__":
    unittest.main()
