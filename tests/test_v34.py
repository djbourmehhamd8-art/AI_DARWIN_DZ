"""v3.4: cases, notes library, interactive checklists, new tools, snooze, durations."""
import os
import sqlite3
import tempfile
import unittest

from bot import checklists
from bot.ai_client import AIClient
from bot.config import Config
from bot.handlers import BotApp
from bot.security import ports, timestamps
from bot.storage import Storage, case_key
from bot.telegram import TelegramAPI
from bot.utils import fmt_duration, parse_duration
from tests import test_integration as ti
from tests.test_ui import cb, message


class Harness(unittest.TestCase):
    __test__ = False

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

    def buttons(self, last=None):
        out = []
        calls = self.calls("sendMessage", "editMessageText")
        for p in (calls[-last:] if last else calls):
            for row in (p.get("reply_markup") or {}).get("inline_keyboard", []):
                out += [b["callback_data"] for b in row]
        return out

    def texts(self):
        return "\n".join(p.get("text", "") for p in self.calls("sendMessage", "editMessageText"))


class Utils(unittest.TestCase):
    def test_compound_durations(self):
        self.assertEqual(parse_duration("1h30m"), 5400)
        self.assertEqual(parse_duration("1d 2h"), 93600)
        self.assertEqual(parse_duration("45"), None)
        self.assertEqual(parse_duration("10m x"), None)
        self.assertEqual(fmt_duration(5400), "1h 30m")
        self.assertEqual(fmt_duration(90000), "1d 1h")
        self.assertEqual(fmt_duration(7200), "2h")


class LocalTools(unittest.TestCase):
    def test_ports(self):
        self.assertEqual([p for p, _ in ports.lookup("22, 3389")], [22, 3389])
        self.assertEqual([p for p, _ in ports.lookup("rdp")], [3389])
        self.assertEqual([p for p, _ in ports.lookup("20-23")], [20, 21, 22, 23])
        self.assertEqual(ports.lookup("99999"), [])

    def test_timestamps(self):
        r = timestamps.analyze("1700000000")
        self.assertIn("2023-11-14 22:13:20 UTC", r["items"][0][1])
        self.assertEqual(timestamps.analyze("2024-05-01T10:00:00Z")["items"][1][1], "1714557600")
        self.assertFalse(timestamps.analyze("not a date")["ok"])

    def test_checklist_data_is_complete(self):
        self.assertEqual(len(checklists.CHECKLISTS), 8)
        for cid, (_, ar, en, items) in checklists.CHECKLISTS.items():
            self.assertTrue(ar and en and 6 <= len(items) <= 10, cid)
            self.assertTrue(all(a and e for a, e in items), cid)
        h = checklists.render("ir", 0b101, "en")
        self.assertIn("2/8", h)
        self.assertIn("<s>", h)


class StorageV34(unittest.TestCase):
    def test_old_db_migrates_case_column(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "old.db")
            c = sqlite3.connect(path)
            c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, first_name TEXT, lang TEXT NOT NULL "
                      "DEFAULT 'ar', persona TEXT NOT NULL DEFAULT 'default', temperature REAL NOT NULL DEFAULT 0.7, "
                      "custom_prompt TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT 'balanced', banned INTEGER "
                      "NOT NULL DEFAULT 0, allowed INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, last_seen "
                      "INTEGER NOT NULL, msgs INTEGER NOT NULL DEFAULT 0, tokens_in INTEGER NOT NULL DEFAULT 0, "
                      "tokens_out INTEGER NOT NULL DEFAULT 0)")
            c.execute("INSERT INTO users(id, created_at, last_seen) VALUES (5, 1, 1)")
            c.commit()
            c.close()
            db = Storage(path)
            self.assertEqual(db.get_user(5)["case_id"], 0)
            self.assertIsNotNone(db.add_case(5, "x"))
            db.close()

    def test_case_limits_and_isolation(self):
        db = Storage(":memory:")
        db.ensure_user_row(1)
        ids = [db.add_case(1, f"c{i}", max_n=3) for i in range(4)]
        self.assertEqual(ids[3], None)
        db.add_message(case_key(ids[0]), "user", "inside case")
        db.add_message(1, "user", "main chat")
        self.assertEqual([m["content"] for m in db.get_history(1)], ["main chat"])
        self.assertEqual([m["content"] for m in db.get_history(case_key(ids[0]))], ["inside case"])
        db.add_note(1, ids[0], "t", "n")
        db.wipe_user(1, 1)
        self.assertEqual((db.list_cases(1), db.count_all_notes(1), db.get_history(case_key(ids[0]))), ([], 0, []))
        db.close()

    def test_note_search_escapes_wildcards(self):
        db = Storage(":memory:")
        db.add_note(1, 0, "a", "100% sure")
        db.add_note(1, 0, "b", "other")
        self.assertEqual(len(db.list_notes(1, 0, query="%")), 1)
        self.assertEqual(len(db.list_notes(1, 0, query="_")), 0)
        db.close()


class Cases(Harness):
    __test__ = True

    def test_case_history_is_separate_and_sent_to_model(self):
        a = self.app
        a.on_message(message(1, "main question"))
        a.on_message(message(1, "/case new Incident A"))
        case = self.db.get_user(1)["case_id"]
        self.assertTrue(case)
        a.on_message(message(1, "case question"))
        sent = [m["content"] for m in ti.SEEN[-1]]
        self.assertNotIn("main question", sent)                         # the model only sees this case
        self.assertIn("case question", sent)
        self.assertIn("Incident A", ti.SEEN[-1][0]["content"])          # and knows which engagement it is
        self.assertEqual(len(self.db.get_history(1)), 2)                # main history untouched
        a.on_message(message(1, "/case main"))
        a.on_message(message(1, "back in main"))
        self.assertIn("main question", [m["content"] for m in ti.SEEN[-1]])
        self.assertNotIn("case question", [m["content"] for m in ti.SEEN[-1]])

    def test_switch_buttons_and_delete(self):
        a = self.app
        a.on_callback(cb(1, "t:case_new"))
        a.on_message(message(1, "Phishing Feb"))
        self.assertEqual(self.db.get_user(1)["case_id"], 1)
        a.on_callback(cb(1, "cs:go:0"))
        self.assertEqual(self.db.get_user(1)["case_id"], 0)
        a.on_callback(cb(1, "cs:go:1"))
        a.on_callback(cb(1, "cs:del"))
        self.assertIn("cs:delyes", self.buttons())
        a.on_callback(cb(1, "cs:delyes"))
        self.assertEqual((self.db.list_cases(1), self.db.get_user(1)["case_id"]), ([], 0))

    def test_cannot_open_someone_elses_case(self):
        self.db.ensure_user_row(2)
        cid = self.db.add_case(2, "secret")
        self.db.set_user(1, allowed=1)
        self.app.on_callback(cb(1, f"cs:go:{cid}"))
        self.assertEqual(self.db.get_user(1)["case_id"], 0)

    def test_groups_ignore_cases(self):
        self.assertEqual(self.app._hk(-100123, {"id": 1, "case_id": 4}), -100123)
        self.assertEqual(self.app._hk(1, {"id": 1, "case_id": 4}), case_key(4))

    def test_export_contains_notes_and_conversation(self):
        a = self.app
        a.on_message(message(1, "/case new Export me"))
        a.on_message(message(1, "hello there"))
        a.on_callback(cb(1, "ans:save"))
        ti.CALLS.clear()
        a.on_callback(cb(1, "cs:export"))
        self.assertTrue(self.calls("sendDocument"))

    def test_report_uses_the_case_history(self):
        a = self.app
        a.on_message(message(1, "/report"))
        self.assertIn("لا توجد محادثة", self.texts())          # nothing to report yet
        a.on_message(message(1, "/case new R1"))
        a.on_message(message(1, "found suspicious logins"))
        a.on_message(message(1, "/report incident"))
        prompt = ti.SEEN[-1][-1]["content"]
        self.assertIn("Executive summary", prompt)
        self.assertIn("R1", prompt)
        self.assertIn("found suspicious logins", [m["content"] for m in ti.SEEN[-1]])


class Notes(Harness):
    __test__ = True

    def test_save_list_view_delete_search(self):
        a = self.app
        a.on_message(message(1, "hello"))
        a.on_callback(cb(1, "ans:save"))
        notes = self.db.list_notes(1, 0)
        self.assertEqual(len(notes), 1)
        self.assertIn("Echo: hello", notes[0]["text"])
        a.on_callback(cb(1, "m:notes"))
        self.assertIn(f"nt:v:{notes[0]['id']}", self.buttons())
        ti.CALLS.clear()
        a.on_callback(cb(1, f"nt:v:{notes[0]['id']}"))
        self.assertIn(f"nt:d:{notes[0]['id']}", self.buttons())
        a.on_callback(cb(1, "t:note_q"))
        ti.CALLS.clear()
        a.on_message(message(1, "Echo"))
        self.assertIn(f"nt:v:{notes[0]['id']}", self.buttons())
        a.on_callback(cb(1, f"nt:d:{notes[0]['id']}"))
        self.assertEqual(self.db.list_notes(1, 0), [])

    def test_pagination(self):
        for i in range(7):
            self.db.add_note(1, 0, f"note {i}", "body")
        self.app.on_callback(cb(1, "m:notes"))
        self.assertIn("nt:p:1", self.buttons())
        ti.CALLS.clear()
        self.app.on_callback(cb(1, "nt:p:1"))
        self.assertEqual(sum(1 for b in self.buttons() if b.startswith("nt:v:")), 2)

    def test_notes_are_per_case_and_per_user(self):
        a = self.app
        a.on_message(message(1, "hello"))
        a.on_callback(cb(1, "ans:save"))
        a.on_message(message(1, "/case new Other"))
        self.assertEqual(self.db.count_notes(1, self.db.get_user(1)["case_id"]), 0)
        self.assertEqual(self.db.get_note(2, 1), None)

    def test_save_masks_secrets(self):
        self.db.ensure_user_row(1)
        self.db.add_message(1, "assistant", "your key is sk-abcdefghijklmnopqrstuvwxyz123456 rotate it")
        self.app.on_callback(cb(1, "ans:save"))
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", self.db.list_notes(1, 0)[0]["text"])

    def test_answer_file_button(self):
        self.app.on_message(message(1, "hello"))
        ti.CALLS.clear()
        self.app.on_callback(cb(1, "ans:file"))
        self.assertTrue(self.calls("sendDocument"))

    def test_answer_keyboard_has_new_buttons(self):
        self.app.on_message(message(1, "hello"))
        data = self.buttons(last=1)
        for want in ("ans:save", "ans:files", "ans:web", "ans:tr", "act:retry"):
            self.assertIn(want, data)


class Checklists(Harness):
    __test__ = True

    def test_menu_toggle_reset_and_save(self):
        a = self.app
        a.on_callback(cb(1, "m:ck"))
        self.assertIn("ck:ir:0:v", self.buttons())
        ti.CALLS.clear()
        a.on_callback(cb(1, "ck:ir:0:v"))
        self.assertIn("ck:ir:0:2", self.buttons())
        ti.CALLS.clear()
        a.on_callback(cb(1, "ck:ir:0:2"))
        self.assertIn("1/8", self.texts())
        self.assertIn("ck:ir:4:2", self.buttons())                       # tapping again un-ticks it
        ti.CALLS.clear()
        a.on_callback(cb(1, "ck:ir:5:r"))
        self.assertIn("0/8", self.texts())
        a.on_callback(cb(1, "ck:ir:3:s"))
        self.assertIn("- [x]", self.db.list_notes(1, 0)[0]["text"])

    def test_bad_data_is_ignored(self):
        for data in ("ck:nope:0:v", "ck:ir:x:1", "ck:ir:0:99", "ck"):
            self.app.on_callback(cb(1, data))                               # must not raise

    def test_command_form(self):
        self.app.on_message(message(1, "/checklist ransom"))
        self.assertIn("ck:ransom:0:0", self.buttons())


class ToolsAndReminders(Harness):
    __test__ = True

    def test_port_tool_via_button(self):
        a = self.app
        a.on_callback(cb(1, "t:port"))
        a.on_message(message(1, "3389"))
        self.assertIn("RDP", self.texts())

    def test_ts_tool(self):
        self.app.on_message(message(1, "/ts 1700000000"))
        self.assertIn("2023-11-14", self.texts())
        ti.CALLS.clear()
        self.app.on_message(message(1, "/ts now"))
        self.assertIn("Unix", self.texts())

    def test_mitre_task_uses_template(self):
        self.app.on_message(message(1, "/mitre T1059.001"))
        self.assertIn("MITRE ATT&CK technique", ti.SEEN[-1][-1]["content"])

    def test_snooze_creates_a_new_reminder(self):
        a = self.app
        c = cb(1, "rem:snz:10")
        c["message"]["text"] = "⏰ check logs"
        a.on_callback(c)
        r = self.db.list_reminders(1)
        self.assertEqual([x["text"] for x in r], ["check logs"])

    def test_dashboard_and_menu(self):
        a = self.app
        a.on_callback(cb(1, "act:me"))
        self.assertIn("📌", self.texts())
        a.on_message(message(1, "/menu"))
        data = self.buttons(last=1)
        for want in ("m:cases", "m:notes", "m:ck", "act:me"):
            self.assertIn(want, data)

    def test_unauthorised_user_cannot_use_workspace(self):
        ti.CALLS.clear()
        self.app.on_callback(cb(2, "m:cases"))
        self.app.on_message(message(2, "/case new hack"))
        self.assertEqual(self.db.list_cases(2), [])


if __name__ == "__main__":
    unittest.main()
