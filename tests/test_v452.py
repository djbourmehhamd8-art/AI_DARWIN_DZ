"""v4.5.2: robust numeric arguments, whitespace-separated command arguments, .env parsing, damaged zip members."""
import io
import os
import struct
import tempfile
import unittest
import zipfile

from bot.config import _bool, _ids, load_env
from bot.files import read_zip_project
from bot.storage import Storage
from bot.utils import parse_duration, safe_int
from tests.test_v34 import Harness


class SafeInt(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(safe_int("42"), 42)
        self.assertEqual(safe_int(" -7 "), -7)
        self.assertEqual(safe_int("٥"), 5)                       # Arabic-Indic digit: int() accepts it

    def test_junk_never_raises(self):
        for bad in ("--5", "²", "", None, "1e3", "12 34", "9" * 5000, "99999999999999999999", "٠٠٠٠٠٠٠٠٠٠٠٠٠٠٠٠٠٠٠٠٠"):
            self.assertIsNone(safe_int(bad), bad)
        self.assertEqual(safe_int("x", 3), 3)

    def test_ids_and_bool(self):
        self.assertEqual(_ids("1, --5, ², 99999999999999999999, -100123"), frozenset({1, -100123}))
        self.assertTrue(_bool("  ", True))
        self.assertFalse(_bool("  ", False))
        self.assertTrue(_bool(" Yes ", False))

    def test_duration_with_huge_number_is_rejected(self):
        self.assertIsNone(parse_duration("9" * 5000 + "d"))
        self.assertEqual(parse_duration("1h30m"), 5400)


class StorageLookups(unittest.TestCase):
    def test_find_and_search_do_not_raise(self):
        db = Storage(":memory:")
        self.addCleanup(db.close)
        db.ensure_user_row(5)
        for q in ("--5", "²", "9" * 40, "-"):
            self.assertIsNone(db.find_user(q))
            self.assertEqual(db.search_users("", q)[1], 0)
        self.assertEqual(db.find_user("5")["id"], 5)

    def test_fact_limit_holds_under_concurrency(self):
        import threading
        db = Storage(":memory:")
        self.addCleanup(db.close)
        threads = [threading.Thread(target=db.add_fact, args=(1, f"f{i}", 5)) for i in range(30)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(len(db.list_facts(1)), 5)


class EnvFile(unittest.TestCase):
    def _load(self, raw: bytes) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, ".env")
            with open(p, "wb") as f:
                f.write(raw)
            load_env(p)

    def tearDown(self):
        for k in ("T452_A", "T452_B", "T452_C", "T452_D"):
            os.environ.pop(k, None)

    def test_bom_does_not_rename_first_key(self):
        self._load("\ufeffT452_A=one\nT452_B=two\n".encode("utf-8"))
        self.assertEqual(os.environ.get("T452_A"), "one")

    def test_comment_after_quoted_value(self):
        self._load(b'T452_C="abc def"   # a comment\nT452_D=\'it"s\'\n')
        self.assertEqual(os.environ.get("T452_C"), "abc def")
        self.assertEqual(os.environ.get("T452_D"), 'it"s')


class BrokenZip(unittest.TestCase):
    def test_bad_member_is_skipped_not_fatal(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("ok.txt", "hello world")
            z.writestr("bad.txt", "corrupt me please")
            z.writestr("odd.txt", "x" * 50)
        raw = bytearray(buf.getvalue())
        raw[raw.find(b"corrupt me please")] ^= 0xFF                # CRC mismatch
        for sig, off, nameoff in ((b"PK\x03\x04", 8, 30), (b"PK\x01\x02", 10, 46)):
            pos = 0
            while (pos := raw.find(sig, pos)) != -1:
                if raw[pos + nameoff:pos + nameoff + 7] == b"odd.txt":
                    raw[pos + off:pos + off + 2] = struct.pack("<H", 9)     # Deflate64: unsupported by zipfile
                pos += 4
        out = read_zip_project(bytes(raw))
        self.assertIn("hello world", out)
        self.assertIn("2 skipped", out)


class Commands(Harness):
    __test__ = True

    def send(self, text, uid=1):
        n = len(self.calls("sendMessage"))
        self.app._safe({"message": {"message_id": 5, "chat": {"id": uid, "type": "private"},
                                    "from": {"id": uid, "first_name": "A"}, "text": text}})
        return [p["text"] for p in self.calls("sendMessage")[n:]]

    def test_newline_separates_command_and_arguments(self):
        self.send("/remember\nmy dog is Rex")
        self.assertEqual([f["text"] for f in self.db.list_facts(1)], ["my dog is Rex"])
        out = self.send("/remind\n10m\ntake a break")
        self.assertTrue(out and "❓" not in out[0])
        self.assertEqual(self.db.list_reminders(1)[0]["text"], "take a break")

    def test_multiline_argument_keeps_inner_newlines(self):
        self.send("/remember line one\nline two")
        self.assertEqual(self.db.list_facts(1)[0]["text"], "line one\nline two")

    def test_oversized_numbers_get_a_usage_reply_not_silence(self):
        for cmd in ("/unremind 99999999999999999999", "/forget 99999999999999999999", "/unremind ²",
                    "/ban 99999999999999999999", "/dm 99999999999999999999 hi", "/case go 99999999999999999999"):
            self.assertTrue(self.send(cmd), cmd)


if __name__ == "__main__":
    unittest.main()
