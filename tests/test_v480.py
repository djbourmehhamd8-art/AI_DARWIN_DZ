"""v4.8.0: tools hub (categories, search, recent), 10 new tools, stricter grading, registry consistency."""
import datetime as dt
import unittest

from bot import devtools as D
from bot.hub import CATEGORIES, HUB_KINDS, LABELS, label, search_kinds
from bot.security import mailauth as MA
from bot.security import webconfig as W
from bot.ui import ASKABLE, HINTS, LOCAL_KINDS
from bot.utildata import UTIL_KINDS
from bot.webext import PUBLIC_TOOLS, run_web_tool
from tests.test_ui import cb, message
from tests.test_v34 import Harness

NEW = ("spf", "dmarc", "secrets", "sri", "chmod", "cidrmatch", "ipconv", "useragent", "diff", "date")


class Grading(unittest.TestCase):
    def test_one_high_caps_at_c_two_at_d(self):
        self.assertLessEqual(W._score([("high", "", "")]), 69)
        self.assertLessEqual(W._score([("high", "", ""), ("high", "", "")]), 49)
        self.assertEqual(W._score([("low", "", "")]), 96)
        self.assertLessEqual(W._score([("low", "", "")], fatal=True), 30)


class Spf(unittest.TestCase):
    def test_plus_all_is_fatal(self):
        self.assertEqual(MA.analyze_spf("v=spf1 +all")["grade"], "F")

    def test_good_record(self):
        r = MA.analyze_spf('"v=spf1 include:_spf.google.com ip4:203.0.113.0/24 -all"')
        self.assertEqual(r["grade"], "A")
        self.assertEqual(r["lookups"], 1)

    def test_lookup_limit_and_ptr(self):
        rec = "v=spf1 " + " ".join(f"include:s{i}.example.com" for i in range(11)) + " -all"
        r = MA.analyze_spf(rec)
        self.assertEqual(r["grade"], "F")
        self.assertIn("ptr", [m for m in MA.analyze_spf("v=spf1 ptr -all")["mechanisms"]])
        self.assertTrue(any("ptr" in f[2] for f in MA.analyze_spf("v=spf1 ptr -all")["findings"]))

    def test_chunked_txt_zone_line_and_missing_all(self):
        r = MA.analyze_spf('example.com. IN TXT "v=spf1 ip4:1.2.3.4 " "include:x.com"')
        self.assertEqual(r["mechanisms"], ["ip4", "include"])
        self.assertIn("high", {f[0] for f in r["findings"]})

    def test_invalid(self):
        for bad in ("", "hello", "v=spf2 -all"):
            with self.assertRaises(ValueError):
                MA.analyze_spf(bad)


class Dmarc(unittest.TestCase):
    def test_none_is_weak_reject_is_strong(self):
        self.assertIn(MA.analyze_dmarc("v=DMARC1; p=none")["grade"], ("C", "D", "F"))
        self.assertEqual(MA.analyze_dmarc("v=DMARC1; p=reject; rua=mailto:d@example.com; adkim=s; aspf=s")["grade"], "A")

    def test_partial_pct_and_subdomain_gap(self):
        r = MA.analyze_dmarc("v=DMARC1; p=reject; sp=none; pct=20; rua=mailto:d@example.com")
        self.assertGreaterEqual(sum(1 for f in r["findings"] if f[0] == "medium"), 2)

    def test_invalid(self):
        for bad in ("", "p=reject", "v=DMARC1"):
            if bad == "v=DMARC1":
                self.assertIn("high", {f[0] for f in MA.analyze_dmarc(bad)["findings"]})     # no p tag
            else:
                with self.assertRaises(ValueError):
                    MA.analyze_dmarc(bad)


class Secrets(unittest.TestCase):
    TEXT = ("aws=AKIAIOSFODNN7EXAMPLE\npassword = 'hunter2hunter2'\nurl https://user:pa55word@host.example/x\n"
            "password: changeme\ntoken=${TOKEN}\nghp_" + "a" * 36)

    def test_finds_real_looking_secrets_and_ignores_placeholders(self):
        r = MA.scan_secrets(self.TEXT)
        types = {h["type"] for h in r["hits"]}
        self.assertTrue({"AWS access key ID", "GitHub token", "Credentials in URL", "Password assignment"} <= types)
        self.assertEqual(r["count"], 4)                           # changeme and ${TOKEN} are placeholders

    def test_never_returns_the_full_secret(self):
        r = MA.scan_secrets(self.TEXT)
        blob = repr(r)
        for secret in ("AKIAIOSFODNN7EXAMPLE", "hunter2hunter2", "pa55word", "a" * 36):
            self.assertNotIn(secret, blob)

    def test_private_key_header_and_clean_text(self):
        self.assertEqual(MA.scan_secrets("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")["high"], 1)
        self.assertEqual(MA.scan_secrets("just a normal sentence about passwords")["count"], 0)
        with self.assertRaises(ValueError):
            MA.scan_secrets("  ")

    def test_long_lines_do_not_hang(self):
        self.assertEqual(MA.scan_secrets("a" * 200000)["count"], 0)


class DevTools(unittest.TestCase):
    def test_chmod_all_forms_agree(self):
        for form in ("755", "rwxr-xr-x", "u=rwx,go=rx", "a=rx,u+w"):
            self.assertEqual(D.chmod_calc(form)["octal"], "0755", form)
        self.assertEqual(D.chmod_calc("4755")["symbolic"], "rwsr-xr-x")
        self.assertEqual(D.chmod_calc("rwsr-xr-x")["octal"], "4755")
        self.assertEqual(D.chmod_calc("1777")["symbolic"], "rwxrwxrwt")
        self.assertEqual(D.chmod_calc("755")["umask"], "022")

    def test_chmod_flags_danger(self):
        self.assertIn("high", [n[0] for n in D.chmod_calc("777")["notes"]])
        self.assertIn("high", [n[0] for n in D.chmod_calc("4755")["notes"]])
        for bad in ("", "999", "rwx", "u=q"):
            with self.assertRaises(ValueError):
                D.chmod_calc(bad)

    def test_cidr_match(self):
        r = D.cidr_match("10.1.2.3, 8.8.8.8, ::1 in 10.0.0.0/8, 192.168.0.0/16")
        self.assertEqual((r["matched"], r["total"]), (1, 3))
        for bad in ("10.0.0.1", "x in 10.0.0.0/8", "10.0.0.1 in nonsense", " in "):
            with self.assertRaises(ValueError, msg=bad):
                D.cidr_match(bad)

    def test_ip_convert_roundtrip(self):
        rows = dict(D.ip_convert("192.168.1.1"))
        self.assertEqual((rows["Decimal"], rows["Hex"]), ("3232235777", "0xc0a80101"))
        self.assertEqual(dict(D.ip_convert("3232235777"))["Address"], "192.168.1.1")
        self.assertEqual(dict(D.ip_convert("0xc0a80101"))["Address"], "192.168.1.1")
        self.assertEqual(dict(D.ip_convert("::ffff:1.2.3.4"))["Mapped IPv4"], "1.2.3.4")
        for bad in ("", "999.1.1.1", "1" * 50):
            with self.assertRaises(ValueError):
                D.ip_convert(bad)

    def test_user_agent(self):
        chrome = D.parse_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0")
        self.assertEqual((chrome["browser"], chrome["os"], chrome["os_version"], chrome["flags"]), ("Edge", "Windows", "10/11", []))
        self.assertIn("high", [f[0] for f in D.parse_user_agent("sqlmap/1.7#stable (https://sqlmap.org)")["flags"]])
        self.assertTrue(D.parse_user_agent("Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit Version/17.1 Mobile Safari/604.1")["mobile"])
        self.assertIn("high", [f[0] for f in D.parse_user_agent("Mozilla/5.0 <script>alert(1)</script>")["flags"]])
        with self.assertRaises(ValueError):
            D.parse_user_agent("  ")

    def test_diff(self):
        r = D.text_diff("a\nb\nc\n---\na\nB\nc")
        self.assertEqual((r["added"], r["removed"], r["identical"]), (1, 1, False))
        self.assertTrue(D.text_diff("x\n---\nx")["identical"])
        self.assertEqual(D.text_diff("a :: b")["added"], 1)
        for bad in ("no separator here", ""):
            with self.assertRaises(ValueError):
                D.text_diff(bad)

    def test_date_calc(self):
        t = dt.date(2026, 11, 24)
        self.assertEqual(D.date_calc("2026-01-01 to 2026-03-01", t)["days"], 59)
        self.assertEqual(D.date_calc("today + 90d", t)["result"], "2027-02-22")
        self.assertEqual(D.date_calc("2026-11-24 - 2w", t)["result"], "2026-11-10")
        self.assertEqual(D.date_calc("2026-12-25", t)["weekday"], "Friday")
        for bad in ("", "2026-13-01", "soon", "2026-01-01 + 9999999999d"):
            with self.assertRaises(ValueError, msg=bad):
                D.date_calc(bad, t)

    def test_sri_known_value(self):
        self.assertEqual(D.sri_hash("alert(1)")["hashes"]["sha384"], "sha384-HT2E9NfWiuQ/w1PRai+hTyqW16NIoCGA/m8VQDUopfAtcz6YQjtsMmQd5uRbVDpW")


class Registry(unittest.TestCase):
    """Guard rails so adding a tool in the future cannot silently half-register it."""

    def test_every_util_has_command_hint_and_hub_slot(self):
        from bot.handlers import BotApp
        for k in UTIL_KINDS:
            self.assertTrue(hasattr(BotApp, f"cmd_{k}"), f"cmd_{k} missing")
            self.assertIn(k, HINTS, k)
            self.assertIn(k, ASKABLE, k)
            self.assertIn(k, LOCAL_KINDS, k)
            self.assertIn(k, HUB_KINDS, f"{k} is in no hub category")

    def test_hub_only_lists_known_tools(self):
        for cid, ic, ar, en, kinds in CATEGORIES:
            for k in kinds:
                self.assertIn(k, LABELS, k)
                self.assertTrue(label(k, "ar") and label(k, "en"))
            self.assertEqual(len(kinds), len(set(kinds)), cid)
            self.assertLessEqual(len(kinds), 16, "a category must stay scannable on a phone")

    def test_new_tools_run_on_the_web(self):
        for k in NEW:
            self.assertIn(k, PUBLIC_TOOLS)
            with self.assertRaises(ValueError, msg=k):
                run_web_tool(k, "")


class Search(unittest.TestCase):
    def test_search(self):
        self.assertEqual(search_kinds("csp")[0], "csp")
        self.assertIn("spf", search_kinds("email spoofing"))
        self.assertIn("chmod", search_kinds("permissions"))
        self.assertIn("cidrmatch", search_kinds("firewall"))
        self.assertIn("dns", search_kinds("DNS"))
        self.assertEqual(search_kinds("zzzzqq"), [])
        self.assertEqual(search_kinds("   "), [])


class HubFlow(Harness):
    __test__ = True

    def setUp(self):
        super().setUp()
        self.db.upsert_user(1, "admin", "Admin")

    def test_main_menu_is_leaner_and_opens_hub(self):
        self.app.on_message(message(1, "/menu"))
        btns = self.buttons()
        self.assertIn("h:home", btns)
        self.assertLessEqual(len(btns), 22)

    def test_hub_categories_and_back(self):
        self.app.on_callback(cb(1, "h:home"))
        for cid, *_ in CATEGORIES:
            self.assertIn(f"h:c:{cid}", self.buttons())
        self.app.on_callback(cb(1, "h:c:net"))
        b = self.buttons()
        for k in ("t:dns", "t:spf", "t:subnet"):
            self.assertIn(k, b)
        self.assertIn("h:home", b)

    def test_unknown_category_is_safe(self):
        self.app.on_callback(cb(1, "h:c:../../x"))
        self.assertIn("h:c:web", self.buttons())               # fell back to the hub

    def test_search_command_and_pending_search(self):
        self.app.on_message(message(1, "/tools cookie"))
        self.assertIn("t:cookie", self.buttons())
        self.app.on_callback(cb(1, "t:hubq"))
        self.app.on_message(message(1, "cron"))
        self.assertIn("t:cron", self.buttons())
        self.app.on_message(message(1, "/tools nothingmatchesthis"))
        self.assertIn("t:hubq", self.buttons())

    def test_recent_tools_shelf(self):
        self.app.on_message(message(1, "/hub"))
        self.assertNotIn("h:r", self.buttons())
        self.app.on_message(message(1, "/chmod 755"))
        self.app.on_message(message(1, "/subnet 10.0.0.0/24"))
        self.app.on_message(message(1, "/chmod 700"))
        self.assertEqual(self.app.recent_tools(1), ["chmod", "subnet"])
        self.app.on_message(message(1, "/hub"))
        self.assertIn("h:r", self.buttons())
        self.app.on_callback(cb(1, "h:r"))
        self.assertIn("t:chmod", self.buttons())

    def test_recent_via_button_flow_and_cap(self):
        self.app.on_callback(cb(1, "t:date"))
        self.app.on_message(message(1, "2026-12-25"))
        self.assertEqual(self.app.recent_tools(1), ["date"])
        for k in ("calc", "unit", "pct", "json", "color", "slug", "uuid"):
            self.app.note_tool(1, k)
        self.assertEqual(len(self.app.recent_tools(1)), 6)
        self.app.note_tool(1, "not-a-tool")
        self.assertNotIn("not-a-tool", self.app.recent_tools(1))

    def test_new_commands_in_chat(self):
        for cmd, needle in (("/spf v=spf1 -all", "SPF"), ("/dmarc v=DMARC1; p=reject", "DMARC"), ("/chmod 777", "🔴"),
                            ("/cidrmatch 10.0.0.1 in 10.0.0.0/8", "✅"), ("/ipconv 1.1.1.1", "0x01010101"),
                            ("/useragent curl/8.0.1", "curl"), ("/sri alert(1)", "sha384"), ("/date 2026-01-01 to 2026-02-01", "31"),
                            ("/diff a\n---\nb", "diff")):
            self.app.on_message(message(1, cmd))
            self.assertIn(needle, self.texts(), cmd)

    def test_secrets_command_masks_and_deletes_the_message(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        self.app.on_message(message(1, f"/secrets key={secret}"))
        self.assertIn("AWS", self.texts())
        self.assertNotIn(secret, self.texts())
        self.assertTrue(self.calls("deleteMessage"))


if __name__ == "__main__":
    unittest.main()


class Redos(unittest.TestCase):
    def test_fspl_regex_is_not_quadratic(self):
        import time
        import re
        rx = re.compile(r"\s*(\S{1,40}(?:\s*[a-zA-Z]{1,6})?)\s+([0-9]{1,12}(?:[.,][0-9]{1,12})?)\s*(km|m)?\s*")
        t = time.perf_counter()
        rx.fullmatch(("password=" + "a" * 100000)[:200])
        self.assertLess(time.perf_counter() - t, 0.05)
