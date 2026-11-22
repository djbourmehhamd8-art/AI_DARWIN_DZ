"""v4.6.0: hosting-ready defaults, public web tools, resilient startup, no secret links in errors."""
import os
import unittest
from unittest.mock import patch

from bot.ai_client import APIError
from bot.config import Config, clean_token, derive_panel_password
from tests.test_v440 import PanelBase


class HostingConfig(unittest.TestCase):
    def cfg(self, **env):
        with patch.dict(os.environ, env, clear=True):
            return Config.from_env()

    def test_only_three_essentials_needed(self):
        c = self.cfg(TELEGRAM_TOKEN="123:abc", API_KEY="k", PORT="8000")
        self.assertEqual(c.validate(), [])
        self.assertEqual((c.web_panel_port, c.web_panel_host), (8000, "0.0.0.0"))
        self.assertGreaterEqual(len(c.web_panel_token), 12)

    def test_token_aliases_and_cleaning(self):
        for name in ("TELEGRAM_BOT_TOKEN", "BOT_TOKEN", "TOKEN"):
            self.assertEqual(self.cfg(**{name: ' "bot123:abc" ', "API_KEY": "k"}).telegram_token, "123:abc")
        self.assertEqual(clean_token("123:a b\n"), "123:ab")

    def test_no_panel_on_a_plain_machine(self):
        c = self.cfg(TELEGRAM_TOKEN="1:a", API_KEY="k")
        self.assertEqual((c.web_panel_port, c.web_panel_host), (0, "127.0.0.1"))

    def test_derived_password_is_stable_and_token_specific(self):
        self.assertEqual(derive_panel_password("1:a"), derive_panel_password("1:a"))
        self.assertNotEqual(derive_panel_password("1:a"), derive_panel_password("1:b"))

    def test_short_explicit_panel_token_does_not_crash_startup(self):
        c = self.cfg(TELEGRAM_TOKEN="1:a", API_KEY="k", WEB_PANEL_PORT="9000", WEB_PANEL_TOKEN="short")
        self.assertEqual(c.validate(), [])
        self.assertGreaterEqual(len(c.web_panel_token), 12)

    def test_missing_essentials_are_reported_not_fatal(self):
        c = self.cfg(PORT="8000")
        self.assertEqual(len(c.validate()), 2)


class ErrorScrub(unittest.TestCase):
    def test_pay_link_never_kept(self):
        e = APIError(402, "No credit. Pay here: https://notrack.ai/api-pay.php?t=SECRET.tok - same key keeps working")
        self.assertNotIn("SECRET", e.message)
        self.assertNotIn("SECRET", str(e))


class PublicTools(PanelBase):
    def test_public_page_and_tool_without_login(self):
        st, _, body = self.req("GET", "/t")
        self.assertEqual(st, 200)
        self.assertIn("/t", body)
        st, _, body = self.req("POST", "/t", {"tool": "calc", "text": "(12+8)*3"})
        self.assertEqual(st, 200)
        self.assertIn("= 60", body)

    def test_public_tools_escape_output_and_hide_admin(self):
        st, _, body = self.req("POST", "/t", {"tool": "b64", "text": "<script>alert(1)</script>"})
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertEqual(self.req("GET", "/audit")[0], 303)          # admin pages still need login

    def test_public_tools_rate_limited_per_ip(self):
        codes = [self.req("POST", "/t", {"tool": "calc", "text": "1+1"})[0] for _ in range(33)]
        self.assertIn(429, codes)

    def test_unknown_tool_refused(self):
        self.assertEqual(self.req("POST", "/t", {"tool": "rm -rf", "text": "x"})[0], 400)

    def test_home_links_to_tools(self):
        self.assertIn('href="/t"', self.req("GET", "/")[2])


class Resilience(PanelBase):
    def test_poll_401_is_not_fatal(self):
        self.app.tg.poll_error = (401, "Unauthorized")
        self.app._poll_failed()                                      # used to raise RuntimeError and kill the process
        self.assertEqual(self.app.tg_state[0], "token_rejected")

    def test_system_page_explains_token_problem(self):
        cookie = self.login()
        self.app.tg_state = ("token_rejected", "Telegram rejected the bot token (401).")
        self.assertIn("401", self.req("GET", "/system", cookie=cookie)[2])


if __name__ == "__main__":
    unittest.main()
