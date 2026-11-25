"""v4.5.1: 409 conflict notice to admins, cheaper quota/audit writes, non-blocking typing indicator."""
import threading
import time
import unittest

from bot.render import Typing
from bot.storage import Storage
from tests import test_integration as ti
from tests.test_v34 import Harness


class Conflict409(Harness):
    __test__ = True

    def test_admins_told_once_per_window(self):
        self.app._notify_conflict()
        self.app._notify_conflict()
        sent = [p for p in self.calls("sendMessage") if p.get("chat_id") == 1 and "409" in p.get("text", "")]
        self.assertEqual(len(sent), 1)
        self.assertTrue(any(a["action"] == "poll_conflict_409" for a in self.db.list_audit(5)))
        self.app._conflict_notified = time.time() - 7 * 3600
        self.app._notify_conflict()
        self.assertEqual(len([p for p in self.calls("sendMessage") if "409" in p.get("text", "")]), 2)

    def test_poll_failed_409_notifies(self):
        self.app.tg.poll_error = (409, "Conflict")
        self.app._poll_failed()
        self.assertTrue(any("409" in p.get("text", "") for p in self.calls("sendMessage")))


class CheaperWrites(unittest.TestCase):
    def test_daily_counts_and_old_rows_pruned(self):
        db = Storage(":memory:")
        self.addCleanup(db.close)
        db._exec("INSERT INTO daily(user_id, day, n) VALUES(7, date('now','-40 day'), 5)")
        for _ in range(3):
            db.bump_daily(7)
        self.assertEqual(db.daily_count(7), 3)
        self.assertIsNone(db._one("SELECT 1 FROM daily WHERE day < date('now','-35 day')"))

    def test_audit_stays_bounded_and_newest_kept(self):
        db = Storage(":memory:")
        self.addCleanup(db.close)
        for i in range(260):
            db.add_audit(1, "a", str(i), keep=100)
        n = db._one("SELECT COUNT(*) n FROM audit")["n"]
        self.assertLessEqual(n, 150)
        self.assertEqual(db.list_audit(1)[0]["detail"], "259")


class TypingNonBlocking(unittest.TestCase):
    def test_enter_returns_before_first_ping(self):
        gate, seen = threading.Event(), []

        class Slow:
            def send_chat_action(self, chat_id):
                seen.append(chat_id)
                gate.wait(2)

        t0 = time.monotonic()
        with Typing(Slow(), 5, every=60):
            self.assertLess(time.monotonic() - t0, 0.5)         # entering never waits for Telegram
            time.sleep(0.2)
            self.assertEqual(seen, [5])
            gate.set()


if __name__ == "__main__":
    unittest.main()
