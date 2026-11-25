"""Regression tests for the deep-audit fixes (locks race, IP deny-list, grid edges, Kp zero, bounded caches, RDAP)."""
import socket
import threading
import time
import unittest
from unittest import mock

from bot import netintel, radiotools, skytools, websearch
from bot.hardening import KeyedLocks, trim_times


class AuditFixes(unittest.TestCase):
    def test_keyed_lock_is_shared_while_in_use_and_released_after(self):
        locks = KeyedLocks(soft_limit=1)
        a = locks["chat"]
        for i in range(50):                       # heavy churn must never hand out a second lock for a key in use
            locks[i]
        self.assertIs(locks["chat"], a)
        del a
        self.assertEqual(len(locks), 0)

    def test_keyed_lock_serialises_threads(self):
        locks, active, peak = KeyedLocks(soft_limit=1), [0], [0]

        def work():
            with locks["k"]:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
                time.sleep(0.002)
                active[0] -= 1
                for i in range(20):
                    locks[("x", i)]
        ts = [threading.Thread(target=work) for _ in range(12)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(peak[0], 1)

    def test_tunnel_and_site_local_addresses_are_not_public(self):
        for ip in ("fec0::1", "2002:7f00:1::", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "::ffff:127.0.0.1",
                   "64:ff9b::7f00:1", "::127.0.0.1", "100.64.0.1", "169.254.169.254", "127.0.0.1", "10.0.0.1"):
            with mock.patch.object(socket, "getaddrinfo", return_value=[(0, 0, 0, "", (ip, 0))]):
                self.assertIsNone(websearch.resolve_public("x.test"), ip)
        with mock.patch.object(socket, "getaddrinfo", return_value=[(0, 0, 0, "", ("8.8.8.8", 0))]):
            self.assertEqual(websearch.resolve_public("x.test"), "8.8.8.8")

    def test_grid_edges_stay_inside_the_alphabet(self):
        for lat, lon in ((90, 180), (-90, -180), (90, -180), (-90, 180), (0, 180)):
            loc = radiotools.to_grid(lat, lon)
            self.assertRegex(loc, r"^[A-R]{2}\d{2}[a-x]{2}$", (lat, lon, loc))
            self.assertIsNotNone(radiotools.from_grid(loc))
        self.assertEqual(radiotools.to_grid(36.75, 3.06)[:4], "JM16")

    def test_kp_zero_is_a_value_not_missing(self):
        self.assertEqual(skytools._last_kp([{"Kp": 0, "time_tag": "t"}]), (0.0, "t"))
        self.assertEqual(skytools._last_kp([{"kp_index": 2, "time_tag": "t"}]), (2.0, "t"))

    def test_trim_times_keeps_newest(self):
        d = {i: float(i) for i in range(100)}
        trim_times(d, 20)
        self.assertLessEqual(len(d), 20)
        self.assertIn(99, d)
        self.assertNotIn(0, d)

    def test_rdap_non_json_body_does_not_raise(self):
        class R:
            status_code = 200
            headers = {}

            def json(self):
                raise ValueError("not json")

        class H:
            def get(self, *a, **k):
                return R()
        with mock.patch.object(websearch, "is_safe_url", return_value=True):
            self.assertEqual(netintel.rdap_domain("example.com", http=H())["ok"], False)

    def test_fetch_text_gives_up_after_the_deadline(self):
        class Slow:
            status_code = 200
            headers = {"Content-Type": "text/html"}
            encoding = "utf-8"

            def iter_content(self, n):
                while True:
                    time.sleep(0.05)
                    yield b"x"

            def close(self):
                pass
        t0 = time.monotonic()
        with mock.patch.object(websearch, "MAX_PAGE_BYTES", 10 ** 9):
            websearch.fetch_text("https://example.com/", timeout=0.05, get=lambda *a, **k: Slow(), resolve=lambda h: "8.8.8.8")
        self.assertLess(time.monotonic() - t0, 20)


if __name__ == "__main__":
    unittest.main()
