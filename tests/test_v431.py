"""v4.3.1: an admin approving a user automatically gives them NEW_USER_LIMIT messages per day (default 100)."""
import dataclasses
import unittest

from bot.config import Config
from tests import test_integration as ti
from tests.test_ui import cb, message
from tests.test_v39 import Base


class WelcomeLimit(Base):
    def setUp(self):
        super().setUp()
        self.app.on_message(message(2, "hello"))        # user 2 shows up, has no access yet
        ti.CALLS.clear()

    def limit(self, uid=2):
        return self.db.get_user(uid)["limit_override"]

    def test_default_is_100_and_configurable(self):
        import os
        from unittest.mock import patch
        base = {"TELEGRAM_TOKEN": "t", "API_KEY": "k"}
        with patch.dict(os.environ, base, clear=True):
            self.assertEqual(Config.from_env().new_user_limit, 100)
        with patch.dict(os.environ, {**base, "NEW_USER_LIMIT": "50"}, clear=True):
            self.assertEqual(Config.from_env().new_user_limit, 50)
        with patch.dict(os.environ, {**base, "NEW_USER_LIMIT": "abc"}, clear=True):
            cfg = Config.from_env()
            self.assertEqual(cfg.new_user_limit, 100)
            self.assertEqual(cfg.validate(), [])

    def test_approve_button_sets_100_and_tells_user(self):
        self.app.on_callback(cb(2, "req:go"))
        ti.CALLS.clear()
        self.app.on_callback(cb(1, "adm:ap:2"))
        self.assertEqual(self.limit(), 100)
        self.assertIn("100", self.texts_to(2))

    def test_all_approval_paths(self):
        for i, data in enumerate(("adm:ap7:%d", "adm:tmp:%d:7", "adm:al:%d"), start=10):
            self.db.ensure_user_row(i, "ar", 0.7)
            self.app.on_callback(cb(1, data % i))
            self.assertEqual(self.limit(i), 100, data)
        self.db.ensure_user_row(20, "ar", 0.7)
        self.app.on_message(message(1, "/allow 20"))
        self.assertEqual(self.limit(20), 100)

    def test_enforced_after_100_and_resets_next_day(self):
        self.app.on_callback(cb(1, "adm:ap:2"))
        for _ in range(100):
            self.db.bump_daily(2)
        ti.CALLS.clear()
        before = self.model_called()
        self.app.on_message(message(2, "one more"))
        self.assertEqual(self.model_called(), before)               # model not called
        self.assertIn("100", self.texts_to(2))                      # told about the daily limit
        self.db._exec("UPDATE daily SET day='2000-01-01' WHERE user_id=2")   # next day
        self.app.on_message(message(2, "new day"))
        self.assertIn("Echo:", self.texts_to(2))

    def test_99_still_allowed(self):
        self.app.on_callback(cb(1, "adm:ap:2"))
        for _ in range(99):
            self.db.bump_daily(2)
        self.app.on_message(message(2, "last one"))
        self.assertIn("Echo:", self.texts_to(2))

    def test_admin_choice_is_never_overwritten(self):
        self.db.set_user(2, limit_override=0)                       # admin made this user unlimited
        self.app.on_callback(cb(1, "adm:ap:2"))
        self.assertEqual(self.limit(), 0)
        self.db.set_user(2, limit_override=250)
        self.app.on_callback(cb(1, "adm:ap:2"))
        self.assertEqual(self.limit(), 250)

    def test_admin_can_still_change_limit_afterwards(self):
        self.app.on_callback(cb(1, "adm:ap:2"))
        self.app.on_callback(cb(1, "adm:lim:2:500"))
        self.assertEqual(self.limit(), 500)

    def test_rejected_or_banned_gets_no_limit(self):
        self.app.on_callback(cb(1, "adm:rj:2"))
        self.assertEqual(self.limit(), -1)
        self.db.set_user(2, banned=1)
        self.app.on_callback(cb(1, "adm:ap:2"))
        self.assertEqual(self.limit(), -1)

    def test_admin_never_limited(self):
        self.assertEqual(self.app.grant_welcome_limit(1), 0)

    def test_feature_off_with_zero(self):
        self.app.cfg = dataclasses.replace(self.app.cfg, new_user_limit=0)
        self.app.on_callback(cb(1, "adm:ap:2"))
        self.assertEqual(self.limit(), -1)
        self.assertEqual(self.db.get_user(2)["allowed"], 1)


if __name__ == "__main__":
    unittest.main()
