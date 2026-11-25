"""5.3.0: Host allow-list on non-loopback binds, extra security headers, no dead handlers, one User-Agent source."""
import dataclasses
import unittest
from pathlib import Path

from tests.test_v440 import PanelBase

ROOT = Path(__file__).resolve().parents[1]


class HostAllowList(PanelBase):
    def _exposed(self, hosts=()):
        self.panel.cfg = dataclasses.replace(self.panel.cfg, web_panel_host="0.0.0.0", web_panel_hosts=hosts)

    def test_exposed_without_allowlist_keeps_old_behaviour(self):
        self._exposed()
        self.assertEqual(self.req("GET", "/", host="anything.example")[0], 200)

    def test_exposed_with_allowlist_rejects_other_hosts(self):
        self._exposed(("panel.example.com",))
        self.assertEqual(self.req("GET", "/", host="evil.example")[0], 403)
        self.assertEqual(self.req("GET", "/", host="panel.example.com")[0], 200)

    def test_healthz_answers_any_host(self):
        self._exposed(("panel.example.com",))
        self.assertEqual(self.req("GET", "/healthz", host="10.0.0.7:8080")[0], 200)


class Headers(PanelBase):
    def test_new_headers_and_hsts_only_on_https(self):
        _, h, _ = self.req("GET", "/")
        self.assertEqual(h["Cross-Origin-Opener-Policy"], "same-origin")
        self.assertIn("camera=()", h["Permissions-Policy"])
        self.assertNotIn("Strict-Transport-Security", h)
        self.panel.cfg = dataclasses.replace(self.panel.cfg, web_panel_url="https://panel.example.com")
        self.assertIn("Strict-Transport-Security", self.req("GET", "/")[1])


class Cleanup(unittest.TestCase):
    def test_single_user_agent_source(self):
        from bot import USER_AGENT, __version__, cvedata, netintel, skytools, websearch
        self.assertEqual(USER_AGENT, f"DarwinBot/{__version__}")
        for mod in (cvedata, netintel, skytools, websearch):
            self.assertIn(USER_AGENT, mod.UA)

    def test_hardened_deploy_files(self):
        self.assertIn("cap_drop", (ROOT / "docker-compose.yml").read_text())
        self.assertIn("SystemCallFilter=@system-service", (ROOT / "deploy" / "darwin.service").read_text())

    def test_commands_still_resolve(self):
        from bot.handlers import BotApp
        from bot.advtools import AdvToolsMixin
        self.assertIs(BotApp.cmd_cve, AdvToolsMixin.cmd_cve)
        self.assertEqual(BotApp.cmd_save.__qualname__, "WebFilesMixin.cmd_save")


if __name__ == "__main__":
    unittest.main()
