"""v4.7.1: regressions found by fuzzing + back-pressure on the update queue."""
import threading
import unittest

from bot import proutils as P
from bot.security import password
from bot.webext import run_web_tool
from tests.test_v34 import Harness


class FuzzRegressions(unittest.TestCase):
    def test_deeply_nested_json_is_a_clean_error(self):
        with self.assertRaises(ValueError):
            P.json_pretty("[" * 5000 + "]" * 5000)
        with self.assertRaises(ValueError):
            run_web_tool("json", "[" * 5000)

    def test_very_long_passphrase_does_not_overflow(self):
        r = password.analyze("aB3$" * 400)
        self.assertEqual(r["crack"], ">1e6 years")
        self.assertTrue(run_web_tool("pass", "x1Y" * 300))

    def test_jwt_garbage_on_web_is_value_error(self):
        for bad in ("", "abc", "a.b.c", "eyJ.eyJ."):
            with self.assertRaises(ValueError, msg=bad):
                run_web_tool("jwt", bad)


class BackPressure(Harness):
    __test__ = True

    def test_slots_are_released_even_when_handler_fails(self):
        n = self.app._slots._value
        self.assertTrue(self.app._take_slot())
        self.app._safe = lambda upd: (_ for _ in ()).throw(RuntimeError("boom"))
        with self.assertRaises(RuntimeError):
            self.app._run_update({})
        self.assertEqual(self.app._slots._value, n)

    def test_full_queue_sheds_instead_of_blocking_forever(self):
        for _ in range(self.app._slots._value):
            self.app._slots.acquire()
        self.app.stop.set()                                # simulate shutdown while saturated: must return promptly
        done = threading.Event()
        threading.Thread(target=lambda: (self.app._take_slot(), done.set()), daemon=True).start()
        self.assertTrue(done.wait(3))


if __name__ == "__main__":
    unittest.main()
