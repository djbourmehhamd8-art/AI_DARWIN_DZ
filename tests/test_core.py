import unittest

from bot.formatting import has_markup, to_html
from bot.storage import Storage
from bot.utils import RateLimiter, fmt_duration, parse_duration, split_text


class UtilsTest(unittest.TestCase):
    def test_split_short(self):
        self.assertEqual(split_text("hi", 10), ["hi"])

    def test_split_long(self):
        text = ("word " * 500).strip()
        parts = split_text(text, 100)
        self.assertTrue(all(len(p) <= 100 for p in parts))
        self.assertEqual(" ".join(p.strip() for p in parts).split(), text.split())

    def test_rate_limiter(self):
        rl = RateLimiter(3, 60)
        self.assertEqual([rl.allow(1) for _ in range(4)], [True, True, True, False])
        self.assertTrue(rl.allow(2))


class StorageTest(unittest.TestCase):
    def setUp(self):
        self.db = Storage(":memory:")
        self.addCleanup(self.db.close)

    def test_user_and_flags(self):
        u = self.db.upsert_user(1, "a", "A")
        self.assertEqual(u["persona"], "default")
        self.db.set_user(1, persona="coder", banned=1)
        u = self.db.get_user(1)
        self.assertEqual((u["persona"], u["banned"]), ("coder", 1))
        with self.assertRaises(ValueError):
            self.db.set_user(1, id=5)

    def test_history_and_retry(self):
        for role, c in [("user", "q1"), ("assistant", "a1"), ("user", "q2"), ("assistant", "a2")]:
            self.db.add_message(10, role, c)
        self.assertEqual(len(self.db.get_history(10, 3)), 3)
        self.assertEqual(self.db.pop_last_exchange(10), "q2")
        self.assertEqual([m["content"] for m in self.db.get_history(10)], ["q1", "a1"])
        self.db.clear_history(10)
        self.assertIsNone(self.db.pop_last_exchange(10))

    def test_usage_stats(self):
        self.db.upsert_user(1, "a", "A")
        self.db.add_usage(1, 100, 50)
        s = self.db.stats()
        self.assertEqual((s["users"], s["msgs"], s["tokens_in"], s["tokens_out"]), (1, 1, 100, 50))

    def test_facts(self):
        self.assertTrue(self.db.add_fact(1, "likes tea", 2))
        self.assertTrue(self.db.add_fact(1, "lives in X", 2))
        self.assertFalse(self.db.add_fact(1, "third", 2))
        facts = self.db.list_facts(1)
        self.assertEqual(len(facts), 2)
        self.assertTrue(self.db.delete_fact(1, facts[0]["id"]))
        self.assertFalse(self.db.delete_fact(2, facts[1]["id"]))   # not your fact
        self.assertEqual(self.db.clear_facts(1), 1)

    def test_reminders(self):
        rid = self.db.add_reminder(1, 10, 100, "a")
        self.db.add_reminder(1, 10, 500, "b")
        self.assertEqual([r["id"] for r in self.db.due_reminders(200)], [rid])
        self.db.finish_reminder(rid)
        self.assertEqual(self.db.due_reminders(200), [])
        self.assertEqual(self.db.count_pending(1), 1)
        self.assertFalse(self.db.delete_reminder(2, rid))

    def test_sqlite_integrity_check(self):
        self.assertEqual(self.db.integrity_check(), "ok")

    def test_daily_and_backup(self):
        self.assertEqual(self.db.daily_count(1), 0)
        self.db.bump_daily(1)
        self.db.bump_daily(1)
        self.assertEqual(self.db.daily_count(1), 2)
        self.assertTrue(self.db.backup_bytes().startswith(b"SQLite format 3"))


class FormattingTest(unittest.TestCase):
    def test_code_block_and_bold(self):
        h = to_html("**hi** <x>\n```python\nif a < b:\n    pass\n```\n`x**2`")
        self.assertIn("<b>hi</b>", h)
        self.assertIn("&lt;x&gt;", h)
        self.assertIn('<pre><code class="language-python">if a &lt; b:', h)
        self.assertIn("<code>x**2</code>", h)       # bold not applied inside inline code
        self.assertTrue(has_markup(h))

    def test_plain_has_no_markup(self):
        self.assertFalse(has_markup(to_html("just <text> & more")))

    def test_heading(self):
        self.assertEqual(to_html("# Title"), "<b>Title</b>")


class DurationTest(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_duration("30s"), 30)
        self.assertEqual(parse_duration("2h"), 7200)
        self.assertEqual(parse_duration("1d"), 86400)
        self.assertIsNone(parse_duration("abc"))
        self.assertEqual(fmt_duration(7200), "2h")


if __name__ == "__main__":
    unittest.main()
