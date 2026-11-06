"""v3.9: access screen + requests, temporary access, moderators, groups with the DZ trigger, toolbox, admin tools."""
import dataclasses
import os
import sqlite3
import tempfile
import time
import unittest

from bot.admin_panel import _cell
from bot.storage import Storage
from bot.ui import kb
from tests import test_integration as ti
from tests.test_ui import cb, message
from tests.test_v34 import Harness

GROUP = -1001


def gmsg(uid, text, chat=GROUP, mid=77, name="Member"):
    return {"message_id": mid, "chat": {"id": chat, "type": "supergroup", "title": "Cyber Group"},
            "from": {"id": uid, "first_name": name}, "text": text}


class Base(Harness):
    __test__ = True

    def to(self, chat_id, *methods):
        return [p for m, p in ti.CALLS if m in (methods or ("sendMessage", "editMessageText")) and p.get("chat_id") == chat_id]

    def texts_to(self, chat_id):
        return "\n".join(p.get("text", "") for p in self.to(chat_id))

    def model_called(self):
        return len(ti.SEEN)


class AccessScreen(Base):
    def test_clear_private_bot_screen_for_new_user(self):
        self.app.on_message(message(2, "hello"))
        txt = self.texts_to(2)
        self.assertIn("بوت خاص", txt)
        self.assertIn("الأمن السيبراني", txt)
        self.assertIn("@DARWIN0DZ", txt)
        self.assertIn("<code>2</code>", txt)
        buttons = [b for p in self.to(2) for row in (p.get("reply_markup") or {}).get("inline_keyboard", []) for b in row]
        self.assertTrue(any(b.get("callback_data") == "req:go" for b in buttons))
        self.assertTrue(any(b.get("url") == "https://t.me/DARWIN0DZ" for b in buttons))
        self.assertEqual(self.model_called(), 0)

    def test_language_toggle_on_access_screen(self):
        self.app.on_message(message(2, "hello"))
        self.app.on_callback(cb(2, "req:lang"))
        self.assertEqual(self.db.get_user(2)["lang"], "en")
        self.assertIn("Private bot", self.texts_to(2))

    def test_kb_url_button_has_no_callback(self):
        b = kb([[("📩 x", "https://t.me/DARWIN0DZ")]])["inline_keyboard"][0][0]
        self.assertEqual(b, {"text": "📩 x", "url": "https://t.me/DARWIN0DZ"})


class AccessRequests(Base):
    def setUp(self):
        super().setUp()
        self.app.on_message(message(2, "hello"))
        ti.CALLS.clear()

    def test_request_reaches_admin_with_buttons_and_cooldown(self):
        self.app.on_callback(cb(2, "req:go"))
        self.assertIn("adm:ap:2", [b["callback_data"] for p in self.to(1) for row in (p.get("reply_markup") or {}).get("inline_keyboard", []) for b in row if "callback_data" in b])
        self.assertGreater(self.db.get_user(2)["requested_at"], 0)
        ti.CALLS.clear()
        self.app.on_callback(cb(2, "req:go"))
        self.assertEqual(self.to(1), [])                                  # no second ping inside the cooldown
        self.assertIn("⏳", self.texts_to(2))

    def test_approve_notifies_user_who_can_then_chat(self):
        self.app.on_callback(cb(2, "req:go"))
        ti.CALLS.clear()
        self.app.on_callback(cb(1, "adm:ap:2"))
        u = self.db.get_user(2)
        self.assertEqual((u["allowed"], u["requested_at"], u["expires_at"]), (1, 0, 0))
        self.assertIn("تم تفعيل حسابك", self.texts_to(2))
        self.app.on_message(message(2, "hello again"))
        self.assertIn("Echo:", self.texts_to(2))

    def test_reject_keeps_user_out_and_notifies(self):
        self.app.on_callback(cb(2, "req:go"))
        ti.CALLS.clear()
        self.app.on_callback(cb(1, "adm:rj:2"))
        self.assertLess(self.db.get_user(2)["requested_at"], 0)
        self.assertIn("تعذّرت الموافقة", self.texts_to(2))
        self.app._denied_shown.clear()                                    # the 20 s anti-flood window
        self.app.on_message(message(2, "hello"))
        self.assertIn("تم رفض طلبك", self.texts_to(2))
        self.assertEqual(self.db.get_user(2)["allowed"], 0)

    def test_banned_user_cannot_request(self):
        self.db.set_user(2, banned=1)
        ti.CALLS.clear()
        self.app.on_callback(cb(2, "req:go"))
        self.assertEqual(self.to(1), [])
        self.assertIn("مقيّد", self.texts_to(2))

    def test_request_with_no_staff_does_not_crash(self):
        self.app.cfg = dataclasses.replace(self.app.cfg, admin_ids=frozenset())
        self.app.on_callback(cb(2, "req:go"))
        self.assertIn("@DARWIN0DZ", self.texts_to(2))
        self.assertEqual(self.db.get_user(2)["requested_at"], 0)


class TemporaryAccess(Base):
    def test_grant_then_expire(self):
        self.app.on_message(message(2, "hi"))
        self.app.on_callback(cb(1, "adm:tmp:2:1"))
        u = self.db.get_user(2)
        self.assertEqual(u["allowed"], 1)
        self.assertAlmostEqual(u["expires_at"], time.time() + 86400, delta=60)
        self.app.on_message(message(2, "still in"))
        self.assertIn("Echo:", self.texts_to(2))
        self.db.set_user(2, expires_at=int(time.time()) - 5)
        ti.CALLS.clear()
        self.app._denied_shown.clear()
        self.app.on_message(message(2, "too late"))
        self.assertEqual(self.db.get_user(2)["allowed"], 0)
        self.assertIn("بوت خاص", self.texts_to(2))
        self.assertTrue(any(a["action"] == "access_expired" for a in self.db.list_audit(10)))

    def test_invalid_days_ignored(self):
        self.app.on_message(message(2, "hi"))
        self.app.on_callback(cb(1, "adm:tmp:2:9999"))
        self.assertEqual(self.db.get_user(2)["allowed"], 0)


class Moderators(Base):
    def setUp(self):
        super().setUp()
        for uid in (2, 3, 4):
            self.app.on_message(message(uid, "hi"))
        self.app.on_callback(cb(1, "adm:mod:2"))                          # admin promotes user 2
        ti.CALLS.clear()

    def test_promotion_and_restricted_panel(self):
        self.assertEqual(self.db.get_user(2)["role"], "mod")
        self.app.on_callback(cb(2, "m:adm"))
        b = self.buttons()
        self.assertIn("adm:rq", b)
        self.assertNotIn("adm:csv", b)
        self.assertNotIn("adm:backup", b)
        self.assertNotIn("adm:gl:0", b)

    def test_mod_can_approve_requests(self):
        self.app.on_callback(cb(3, "req:go"))
        self.assertIn("adm:ap:3", [b["callback_data"] for p in self.to(2) for row in (p.get("reply_markup") or {}).get("inline_keyboard", []) for b in row if "callback_data" in b])
        self.app.on_callback(cb(2, "adm:ap:3"))
        self.assertEqual(self.db.get_user(3)["allowed"], 1)

    def test_mod_cannot_use_admin_only_actions(self):
        for data in ("adm:csv", "adm:backup", "adm:mnt", "adm:keys", "adm:gl:0", "adm:mod:3", "adm:lim:3:10", "adm:dm:3", "adm:cy:3"):
            ti.CALLS.clear()
            self.app.on_callback(cb(2, data))
            self.assertEqual(self.calls("sendDocument"), [], data)
        self.assertEqual(self.db.get_user(3)["role"], "")
        self.assertFalse(self.app.maintenance)
        self.assertEqual(self.db.get_user(3)["limit_override"], -1)

    def test_mod_cannot_touch_admin_mod_or_self(self):
        self.app.on_callback(cb(1, "adm:mod:4"))                          # a second moderator
        for target in (1, 2, 4):
            self.app.on_callback(cb(2, f"adm:ban:{target}"))
            row = self.db.get_user(target)
            self.assertEqual(row["banned"] if row else 0, 0, target)
        self.app.on_callback(cb(2, "adm:ban:3"))                          # an ordinary user is fine
        self.assertEqual(self.db.get_user(3)["banned"], 1)

    def test_demotion_and_non_staff_cannot_open_panel(self):
        self.app.on_callback(cb(1, "adm:mod:2"))
        self.assertEqual(self.db.get_user(2)["role"], "")
        ti.CALLS.clear()
        self.app.on_callback(cb(3, "m:adm"))
        self.assertNotIn("adm:rq", self.buttons())

    def test_mod_panel_command(self):
        self.app.on_callback(cb(1, "adm:mod:2")); self.app.on_callback(cb(1, "adm:mod:2"))   # off, then on again
        self.assertEqual(self.db.get_user(2)["role"], "mod")
        self.db.set_user(2, allowed=1)
        ti.CALLS.clear()
        self.app.on_message(message(2, "/panel"))
        self.assertIn("adm:rq", self.buttons())


class AdminTools(Base):
    def setUp(self):
        super().setUp()
        self.app.on_message(message(2, "hi"))
        ti.CALLS.clear()

    def test_direct_message_button_flow(self):
        self.app.on_callback(cb(1, "adm:dm:2"))
        self.app.on_message(message(1, "welcome aboard"))
        self.assertIn("welcome aboard", self.texts_to(2))
        self.assertIn("📩", self.texts_to(2))

    def test_dm_command_and_validation(self):
        self.app.on_message(message(1, "/dm 2 hello there"))
        self.assertIn("hello there", self.texts_to(2))
        ti.CALLS.clear()
        self.app.on_message(message(1, "/dm abc"))
        self.assertIn("/dm", self.texts_to(1))

    def test_limit_override(self):
        self.db.set_user(2, allowed=1)
        self.app.on_callback(cb(1, "adm:lim:2:10"))
        self.assertEqual(self.db.get_user(2)["limit_override"], 10)
        for _ in range(10):
            self.db.bump_daily(2)
        ti.CALLS.clear()
        self.app.on_message(message(2, "one more"))
        self.assertEqual(self.model_called(), 0)
        self.app.on_callback(cb(1, "adm:lim:2:0"))                        # unlimited
        self.app.on_message(message(2, "one more"))
        self.assertIn("Echo:", self.texts_to(2))
        self.app.on_callback(cb(1, "adm:lim:2:d"))
        self.assertEqual(self.db.get_user(2)["limit_override"], -1)

    def test_csv_export_and_formula_injection(self):
        self.db.upsert_user(9, "=cmd", "+evil")
        self.app.on_callback(cb(1, "adm:csv"))
        self.assertTrue(self.calls("sendDocument"))
        self.assertEqual(_cell("=1+1"), "'=1+1")
        self.assertEqual(_cell("@x"), "'@x")
        self.assertEqual(_cell("safe"), "safe")

    def test_top_users_and_groups_screens(self):
        self.db.add_usage(2, 5, 5)
        self.app.on_callback(cb(1, "adm:top"))
        self.assertIn("adm:u:2", self.buttons())
        self.db.upsert_chat(GROUP, "Cyber Group")
        self.app.on_callback(cb(1, "adm:gl:0"))
        self.assertIn(f"adm:gc:{GROUP}", self.buttons())
        self.app.on_callback(cb(1, f"adm:gok:{GROUP}"))
        self.assertEqual(self.db.get_chat(GROUP)["allowed"], 1)
        self.app.on_callback(cb(1, f"adm:grv:{GROUP}"))
        self.assertEqual(self.db.get_chat(GROUP)["allowed"], 0)
        self.app.on_callback(cb(1, f"adm:glv:{GROUP}"))
        self.assertIsNone(self.db.get_chat(GROUP))
        self.assertTrue(any(m == "leaveChat" for m, _ in ti.CALLS))


class GroupTrigger(Base):
    def test_trigger_parsing(self):
        g = self.app.group_trigger
        self.assertEqual(g("DZ كم عدد دول العالم؟"), "كم عدد دول العالم؟")
        self.assertEqual(g("dz: how many countries?"), "how many countries?")
        self.assertEqual(g("Dz, سؤال"), "سؤال")
        self.assertEqual(g("دي زد ما هو DNS؟"), "ما هو DNS؟")
        self.assertEqual(g("DZ"), "")
        self.assertIsNone(g("dzone is a site"))
        self.assertIsNone(g("hello DZ question"))
        self.assertIsNone(g("Darwin was a naturalist"))


class Groups(Base):
    def setUp(self):
        super().setUp()
        self.app.bot_id = 4242
        self.app.on_message(message(2, "hi"))
        ti.CALLS.clear()
        ti.SEEN.clear()

    def test_unauthorised_group_gets_notice_and_staff_ping(self):
        self.app.on_message(gmsg(2, "DZ كم عدد دول العالم؟"))
        self.assertEqual(self.model_called(), 0)
        self.assertIn("غير مفعّلة", self.texts_to(GROUP))
        self.assertIn(f"adm:gok:{GROUP}", [b["callback_data"] for p in self.to(1) for row in (p.get("reply_markup") or {}).get("inline_keyboard", []) for b in row if "callback_data" in b])
        ti.CALLS.clear()
        self.app.on_message(gmsg(2, "DZ again"))                          # throttled: one notice per hour
        self.assertEqual(self.to(GROUP), [])
        self.assertEqual(self.to(1), [])

    def test_authorised_group_answers_the_question_in_a_thread(self):
        self.db.upsert_chat(GROUP, "Cyber Group")
        self.db.set_chat_allowed(GROUP, True)
        self.app.on_message(gmsg(2, "DZ كم عدد دول العالم؟", mid=555))
        self.assertEqual(self.model_called(), 1)
        self.assertEqual(ti.SEEN[-1][-1]["content"], "كم عدد دول العالم؟")             # trigger word stripped
        self.assertIn("GROUP CHAT", ti.SEEN[-1][0]["content"])
        first = self.to(GROUP, "sendMessage")[0]
        self.assertEqual(first["reply_parameters"]["message_id"], 555)
        self.assertIn("Echo:", self.texts_to(GROUP))
        self.assertIsNone(self.to(GROUP, "sendMessage", "editMessageText")[-1].get("reply_markup"))   # no big keyboard in groups

    def test_ordinary_chatter_is_ignored(self):
        self.db.upsert_chat(GROUP, "Cyber Group")
        self.db.set_chat_allowed(GROUP, True)
        self.app.on_message(gmsg(2, "just talking about dzone and darwin"))
        self.assertEqual(self.model_called(), 0)
        self.assertEqual(self.to(GROUP), [])

    def test_members_get_only_safe_commands(self):
        self.db.upsert_chat(GROUP, "Cyber Group")
        self.db.set_chat_allowed(GROUP, True)
        self.app.on_message(gmsg(2, "/export"))
        self.app.on_message(gmsg(2, "/system hack"))
        self.assertEqual(self.calls("sendDocument"), [])
        self.assertEqual(self.db.get_user(2)["custom_prompt"], "")
        ti.CALLS.clear()
        self.app.on_message(gmsg(2, "/help"))
        self.assertTrue(self.to(GROUP))

    def test_banned_member_is_ignored_even_in_authorised_group(self):
        self.db.upsert_chat(GROUP, "G")
        self.db.set_chat_allowed(GROUP, True)
        self.db.set_user(2, banned=1)
        self.app.on_message(gmsg(2, "DZ hello"))
        self.assertEqual(self.model_called(), 0)

    def test_group_member_daily_limit(self):
        self.app.cfg = dataclasses.replace(self.app.cfg, group_member_limit=2)
        self.db.upsert_chat(GROUP, "G")
        self.db.set_chat_allowed(GROUP, True)
        for _ in range(2):
            self.db.bump_daily(2)
        self.app.on_message(gmsg(2, "DZ third question"))
        self.assertEqual(self.model_called(), 0)

    def test_allowgroup_and_revokegroup_by_admin_only(self):
        self.app.on_message(gmsg(2, "/allowgroup"))
        self.assertIsNone(self.db.get_chat(GROUP) and self.db.get_chat(GROUP)["allowed"] or None)
        self.app.on_message(gmsg(1, "/allowgroup", name="Boss"))
        self.assertEqual(self.db.get_chat(GROUP)["allowed"], 1)
        self.app.on_message(gmsg(1, "/revokegroup", name="Boss"))
        self.assertEqual(self.db.get_chat(GROUP)["allowed"], 0)

    def test_admin_adding_the_bot_authorises_the_group_and_welcomes(self):
        ev = {"chat": {"id": GROUP, "type": "supergroup", "title": "Cyber Group"}, "from": {"id": 1, "first_name": "Boss"},
              "old_chat_member": {"status": "left"}, "new_chat_member": {"status": "member"}}
        self.app.on_my_chat_member(ev)
        self.assertEqual(self.db.get_chat(GROUP)["allowed"], 1)
        self.assertIn("DZ", self.texts_to(GROUP))
        ti.CALLS.clear()
        self.app.on_my_chat_member(ev)                                    # duplicate event within a minute
        self.assertEqual(self.to(GROUP), [])

    def test_stranger_adding_the_bot_leaves_it_waiting_and_pings_admin(self):
        ev = {"chat": {"id": GROUP, "type": "supergroup", "title": "Cyber Group"}, "from": {"id": 2, "first_name": "Stranger"},
              "old_chat_member": {"status": "left"}, "new_chat_member": {"status": "member"}}
        self.app.on_my_chat_member(ev)
        self.assertEqual(self.db.get_chat(GROUP)["allowed"], 0)
        self.assertIn("بانتظار موافقة", self.texts_to(GROUP))
        self.assertTrue(self.to(1))
        self.app.on_my_chat_member({**ev, "old_chat_member": {"status": "member"}, "new_chat_member": {"status": "kicked"}})
        self.assertIsNone(self.db.get_chat(GROUP))

    def test_service_message_fallback_welcomes_once(self):
        m = {"message_id": 1, "chat": {"id": GROUP, "type": "supergroup", "title": "T"}, "from": {"id": 1, "first_name": "Boss"},
             "new_chat_members": [{"id": 4242, "is_bot": True}]}
        self.app.on_message(m)
        self.assertIn("DZ", self.texts_to(GROUP))

    def test_group_open_mode_answers_without_authorisation(self):
        self.app.cfg = dataclasses.replace(self.app.cfg, group_open=True)
        self.app.on_message(gmsg(2, "DZ hello"))
        self.assertEqual(self.model_called(), 1)

    def test_bare_trigger_shows_usage(self):
        self.db.upsert_chat(GROUP, "G")
        self.db.set_chat_allowed(GROUP, True)
        self.app.on_message(gmsg(2, "DZ"))
        self.assertEqual(self.model_called(), 0)
        self.assertIn("كم عدد دول العالم", self.texts_to(GROUP))


class Round2Fixes(Base):
    """Defects found in the second audit pass of the 3.9.0 code."""

    def setUp(self):
        super().setUp()
        for uid in (2, 3):
            self.app.on_message(message(uid, "hi"))
        ti.CALLS.clear()

    def test_stale_approve_button_cannot_unban(self):
        self.db.set_user(2, banned=1, requested_at=int(time.time()))      # banned after the request was sent
        for data in ("adm:ap:2", "adm:ap7:2", "adm:tmp:2:7"):
            self.app.on_callback(cb(1, data))
        u = self.db.get_user(2)
        self.assertEqual((u["banned"], u["allowed"]), (1, 0))

    def test_cancelled_dm_target_is_never_reused(self):
        self.app.on_callback(cb(1, "adm:dm:2"))                           # admin starts a DM, then abandons it
        self.app.on_callback(cb(1, "x:cancel"))
        ti.CALLS.clear()
        self.app.on_message(message(1, "/dm 3 hello three"))
        self.assertIn("hello three", self.texts_to(3))
        self.assertNotIn("hello three", self.texts_to(2))

    def test_dm_command_requires_numeric_id(self):
        self.app.on_message(message(1, "/dm hello there"))
        self.assertNotIn("hello there", self.texts_to(2) + self.texts_to(3))

    def test_access_screen_is_throttled(self):
        ti.CALLS.clear()
        self.app.on_message(message(2, "one"))
        self.app._denied_shown.clear()
        self.app.on_message(message(2, "two"))
        before = len(self.to(2))
        for i in range(5):
            self.app.on_message(message(2, f"spam {i}"))
        self.assertEqual(len(self.to(2)), before)

    def test_request_flood_does_not_ping_staff_forever(self):
        for uid in range(100, 125):
            self.db.upsert_user(uid, f"u{uid}", "U")
            self.app.on_message(message(uid, "hi"))
        ti.CALLS.clear()
        for uid in range(100, 125):
            self.app.on_callback(cb(uid, "req:go"))
        pings = [p for p in self.to(1) if "adm:ap:" in str(p.get("reply_markup"))]
        self.assertLessEqual(len(pings), 15)


class Toolbox(Base):
    def test_commands(self):
        self.app.on_message(message(1, "/hex 255"))
        self.assertIn("0xff", self.texts())
        self.app.on_message(message(1, "/caesar Uryyb Jbeyq"))
        self.assertIn("Hello World", self.texts())
        self.app.on_message(message(1, "/entropy aaaaaaaaaaaaaaaaaaaa"))
        self.assertIn("bits/char", self.texts())

    def test_menu_buttons_and_usage(self):
        self.app.on_callback(cb(1, "m:tools"))
        for want in ("t:hex", "t:caesar", "t:entropy"):
            self.assertIn(want, self.buttons())
        ti.CALLS.clear()
        self.app.on_callback(cb(1, "t:hex"))
        self.app.on_message(message(1, "hello"))
        self.assertIn("68 65 6c 6c 6f", self.texts())
        ti.CALLS.clear()
        self.app.on_message(message(1, "/hex"))
        self.assertIn("/hex", self.texts())


class Migration(unittest.TestCase):
    def test_old_database_gets_new_columns_and_chats_table(self):
        path = os.path.join(tempfile.mkdtemp(), "old.db")
        c = sqlite3.connect(path)
        c.executescript("""CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, first_name TEXT,
            lang TEXT NOT NULL DEFAULT 'ar', persona TEXT NOT NULL DEFAULT 'default', temperature REAL NOT NULL DEFAULT 0.7,
            custom_prompt TEXT NOT NULL DEFAULT '', banned INTEGER NOT NULL DEFAULT 0, allowed INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL, msgs INTEGER NOT NULL DEFAULT 0,
            tokens_in INTEGER NOT NULL DEFAULT 0, tokens_out INTEGER NOT NULL DEFAULT 0);
            INSERT INTO users(id, created_at, last_seen) VALUES(5, 1, 1);""")
        c.commit()
        c.close()
        s = Storage(path)
        u = s.get_user(5)
        self.assertEqual((u["allowed"], u["requested_at"], u["expires_at"], u["role"], u["limit_override"]), (1, 0, 0, "", -1))
        self.assertEqual(s.upsert_chat(-5, "T")["allowed"], 0)
        s.close()


if __name__ == "__main__":
    unittest.main()
