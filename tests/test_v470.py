"""v4.7.0: CSP / cookie / security-header auditors, subnet calculator, cron explainer (bot + web)."""
import datetime as dt
import unittest

from bot import proutils as P
from bot.security import webconfig as W
from bot.utildata import UTIL_KINDS
from bot.webext import PUBLIC_TOOLS, run_web_tool
from tests.test_ui import cb, message
from tests.test_v34 import Harness

STRONG_CSP = ("default-src 'none'; script-src 'self' 'nonce-abc123' 'strict-dynamic'; object-src 'none'; base-uri 'none'; "
              "frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests; report-to csp")
GOOD_HEADERS = """HTTP/2 200
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: """ + STRONG_CSP + """
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Set-Cookie: __Host-sid=abcdefghijklmnopqrstuv; Path=/; Secure; HttpOnly; SameSite=Lax
"""


def sev(res):
    return {f[0] for f in res["findings"]}


class CspTests(unittest.TestCase):
    def test_strong_policy_scores_high(self):
        r = W.analyze_csp(STRONG_CSP)
        self.assertEqual(r["grade"], "A")
        self.assertNotIn("high", sev(r))

    def test_weak_policy_flags_unsafe_inline_eval_wildcard(self):
        r = W.analyze_csp("script-src * 'unsafe-inline' 'unsafe-eval' data:")
        self.assertIn("high", sev(r))
        self.assertIn(r["grade"], ("D", "F"))
        self.assertGreaterEqual(sum(1 for f in r["findings"] if f[0] == "high"), 3)

    def test_nonce_neutralises_unsafe_inline(self):
        r = W.analyze_csp("script-src 'nonce-x' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
        self.assertFalse(any(f[0] == "high" for f in r["findings"]))

    def test_missing_script_src_is_high_and_header_prefix_is_stripped(self):
        r = W.analyze_csp("Content-Security-Policy: img-src *")
        self.assertIn("high", sev(r))
        self.assertIn("img-src", r["directives"])

    def test_bypass_host_and_first_directive_wins(self):
        r = W.analyze_csp("script-src https://cdn.jsdelivr.net; script-src 'unsafe-inline'")
        self.assertEqual(W.parse_csp("a 1; a 2")["a"], ["1"])
        self.assertTrue(any("jsdelivr" in f[2] for f in r["findings"]))

    def test_empty_rejected(self):
        for bad in ("", "   ", ";;;"):
            with self.assertRaises(ValueError):
                W.analyze_csp(bad)


class CookieTests(unittest.TestCase):
    def test_hardened_cookie_is_clean(self):
        r = W.analyze_cookie("Set-Cookie: __Host-sid=abcdefghijklmnopqrstuv; Path=/; Secure; HttpOnly; SameSite=Strict")
        self.assertEqual(r["grade"], "A")
        self.assertNotIn("high", sev(r))

    def test_session_cookie_without_flags(self):
        r = W.analyze_cookie("sessionid=abc123; Path=/")
        self.assertEqual(sum(1 for f in r["findings"] if f[0] == "high"), 2)   # Secure + HttpOnly

    def test_value_is_never_echoed(self):
        secret = "SUPERSECRETVALUE9999"
        r = W.analyze_cookie(f"token={secret}; Path=/")
        self.assertNotIn(secret, repr(r))
        self.assertEqual(r["value_len"], len(secret))

    def test_samesite_none_without_secure_and_bad_prefix(self):
        self.assertIn("high", sev(W.analyze_cookie("a=b; SameSite=None")))
        r = W.analyze_cookie("__Host-x=1; Secure; Path=/app")
        self.assertTrue(any("__Host-" in f[2] for f in r["findings"]))

    def test_invalid_line(self):
        for bad in ("", "novalue; Secure", "=x"):
            with self.assertRaises(ValueError):
                W.analyze_cookie(bad)


class HeaderTests(unittest.TestCase):
    def test_good_headers(self):
        r = W.analyze_headers(GOOD_HEADERS)
        self.assertIn(r["grade"], ("A", "B"))
        self.assertNotIn("high", sev(r))

    def test_bad_headers(self):
        r = W.analyze_headers("HTTP/1.1 200 OK\nServer: Apache/2.4.1\nAccess-Control-Allow-Origin: null\nX-Powered-By: PHP/5.6")
        self.assertEqual(r["grade"], "F")
        self.assertGreaterEqual(sum(1 for f in r["findings"] if f[0] == "high"), 3)

    def test_parser_ignores_junk_and_folds_lines(self):
        hs, n = W.parse_headers("HTTP/1.1 200 OK\nnot a header\nX-A: 1\n  more\nx-a: 2")
        self.assertEqual(n, 2)
        self.assertEqual(hs["x-a"], ["1 more", "2"])
        with self.assertRaises(ValueError):
            W.analyze_headers("just text without any header")


class SubnetTests(unittest.TestCase):
    def test_cidr_and_host_bits(self):
        r = P.subnet_calc("192.168.1.10/24")
        self.assertEqual((r["network"], r["broadcast"], r["hosts"]), ("192.168.1.0", "192.168.1.255", 254))

    def test_mask_form_and_edge_prefixes(self):
        self.assertEqual(P.subnet_calc("10.0.0.0 255.255.255.0")["cidr"], "10.0.0.0/24")
        self.assertEqual(P.subnet_calc("10.0.0.0/31")["hosts"], 2)
        self.assertEqual(P.subnet_calc("10.0.0.1/32")["hosts"], 1)

    def test_split(self):
        r = P.subnet_calc("10.0.0.0/24 /26")
        self.assertEqual(r["subnets"], ["10.0.0.0/26", "10.0.0.64/26", "10.0.0.128/26", "10.0.0.192/26"])
        self.assertEqual(P.subnet_calc("10.0.0.0/8 to 24")["subnet_count"], 65536)
        self.assertEqual(len(P.subnet_calc("10.0.0.0/8 to 24")["subnets"]), 16)

    def test_ipv6_and_errors(self):
        self.assertEqual(P.subnet_calc("2001:db8::/32")["version"], 6)
        for bad in ("", "999.1.1.1/24", "10.0.0.0/24 /24", "10.0.0.0/24 /20", "10.0.0.0/8 /30", "hello"):
            with self.assertRaises(ValueError, msg=bad):
                P.subnet_calc(bad)


class CronTests(unittest.TestCase):
    START = dt.datetime(2026, 11, 23, 10, 7, tzinfo=dt.timezone.utc)      # a Monday

    def test_every_15_minutes(self):
        r = P.cron_explain("*/15 * * * *", 3, self.START)
        self.assertEqual([x[11:16] for x in r["next"]], ["10:15", "10:30", "10:45"])

    def test_weekdays_and_names(self):
        r = P.cron_explain("0 3 * * mon-fri", 3, self.START)
        self.assertEqual([x[:10] for x in r["next"]], ["2026-11-24", "2026-11-25", "2026-11-26"])

    def test_sunday_as_7_and_macros(self):
        self.assertIn("(Sun)", P.cron_explain("0 0 * * 7", 1, self.START)["next"][0])
        self.assertEqual(P.cron_explain("@hourly", 1, self.START)["next"][0][11:16], "11:00")

    def test_dom_dow_or_semantics(self):
        r = P.cron_explain("0 0 1 * 5", 4, self.START)
        self.assertTrue(r["dom_dow_or"])
        self.assertEqual([x[:10] for x in r["next"]], ["2026-11-27", "2026-12-01", "2026-12-04", "2026-12-11"])

    def test_leap_day(self):
        self.assertEqual(P.cron_explain("0 0 29 2 *", 1, self.START)["next"][0][:10], "2028-02-29")

    def test_invalid(self):
        for bad in ("", "* * *", "61 * * * *", "*/0 * * * *", "a b c d e", "5-1 * * * *", "* * 32 * *", "1,,2 * * * *"):
            with self.assertRaises(ValueError, msg=bad):
                P.cron_explain(bad)


class WebToolTests(unittest.TestCase):
    def test_new_tools_are_public_and_run(self):
        samples = {"csp": STRONG_CSP, "cookie": "a=b; Secure; HttpOnly; SameSite=Lax", "secheaders": GOOD_HEADERS,
                   "subnet": "10.0.0.0/24", "cron": "*/5 * * * *"}
        for k, v in samples.items():
            self.assertIn(k, PUBLIC_TOOLS)
            self.assertTrue(run_web_tool(k, v), k)

    def test_web_tool_bad_input_raises_value_error(self):
        for k in ("csp", "cookie", "secheaders", "subnet", "cron"):
            with self.assertRaises(ValueError, msg=k):
                run_web_tool(k, "")

    def test_every_new_kind_registered(self):
        for k in ("csp", "cookie", "secheaders", "subnet", "cron"):
            self.assertIn(k, UTIL_KINDS)


class BotFlow(Harness):
    __test__ = True

    def setUp(self):
        super().setUp()
        self.db.upsert_user(1, "admin", "Admin")

    def test_commands(self):
        for cmd, needle in (("/subnet 192.168.1.10/24", "254"), ("/cron */15 * * * *", "UTC"),
                            ("/csp script-src 'unsafe-inline'", "🔴"), ("/cookie sid=abc; Path=/", "🍪"),
                            ("/secheaders Server: nginx/1.18.0", "🧱")):
            self.app.on_message(message(1, cmd))
            self.assertIn(needle, self.texts(), cmd)

    def test_button_flow_and_bad_input(self):
        self.app.on_callback(cb(1, "t:subnet"))
        self.app.on_message(message(1, "10.0.0.0/30"))
        self.assertIn("10.0.0.3", self.texts())
        self.app.on_message(message(1, "/cron nonsense"))
        self.assertIn("⚠️", self.texts())

    def test_cookie_value_not_echoed_in_chat(self):
        self.app.on_message(message(1, "/cookie token=TOPSECRETVALUE123; Path=/"))
        self.assertNotIn("TOPSECRETVALUE123", self.texts())


if __name__ == "__main__":
    unittest.main()
