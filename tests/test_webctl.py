"""Web panel control pages: groups, settings (maintenance, limits), broadcast, backup, user roles. Real HTTP on a local port."""
import time
import unittest

from bot.webctl import WebCtlMixin
from tests.test_v440 import PanelBase


class CtlBase(PanelBase):
    __test__ = True

    def setUp(self):
        super().setUp()
        self.db.upsert_chat(-100, "<b>Team</b>")
        self.cookie = self.login()
        self.tok = self.csrf(self.cookie)

    def post(self, path, **kw):
        return self.req("POST", path, {"csrf": self.tok, **kw}, cookie=self.cookie)

    def flash_of(self, path):
        return self.req("GET", path, cookie=self.cookie)[2]


class Access(CtlBase):
    def test_pages_need_login_and_csrf(self):
        for path in ("/groups", "/settings"):
            st, _, body = self.req("GET", path)
            self.assertEqual(st, 303)                                              # redirected to login, never the data
            self.assertNotIn("Team", body)
        for path in ("/groups/act", "/settings/save", "/settings/broadcast", "/settings/backup", "/user/ctl"):
            self.assertEqual(self.req("POST", path, {"x": "1"})[0], 403)           # no session
            self.assertEqual(self.req("POST", path, {"csrf": "bad"}, cookie=self.cookie)[0], 403)

    def test_nav_links(self):
        body = self.flash_of("/groups")
        self.assertIn('href="/settings"', body)
        self.assertIn('href="/groups"', body)


class Groups(CtlBase):
    def test_list_escapes_title(self):
        body = self.flash_of("/groups")
        self.assertNotIn("<b>Team</b>", body)
        self.assertIn("&lt;b&gt;Team&lt;/b&gt;", body)

    def test_allow_revoke_limit(self):
        self.assertEqual(self.post("/groups/act", cid="-100", act="allow")[0], 303)
        self.assertEqual(self.db.get_chat(-100)["allowed"], 1)
        self.post("/groups/act", cid="-100", act="limit", value="50")
        self.assertEqual(self.db.get_chat(-100)["daily_limit"], 50)
        self.post("/groups/act", cid="-100", act="limit", value="d")
        self.assertEqual(self.db.get_chat(-100)["daily_limit"], -1)
        self.post("/groups/act", cid="-100", act="limit", value="999")             # not an offered choice
        self.assertEqual(self.db.get_chat(-100)["daily_limit"], -1)
        self.post("/groups/act", cid="-100", act="revoke")
        self.assertEqual(self.db.get_chat(-100)["allowed"], 0)
        actions = [a["action"] for a in self.db.list_audit(20)]
        self.assertIn("web_group_allow", actions)
        self.assertIn("web_group_revoke", actions)

    def test_leave_needs_confirmation(self):
        self.post("/groups/act", cid="-100", act="leave")
        self.assertIsNotNone(self.db.get_chat(-100))
        self.post("/groups/act", cid="-100", act="leave", confirm="1")
        self.assertIsNone(self.db.get_chat(-100))

    def test_unknown_group(self):
        self.post("/groups/act", cid="-555", act="allow")
        self.assertIn("غير موجودة", self.flash_of("/groups"))


class Settings(CtlBase):
    def test_maintenance_toggle_persists(self):
        self.post("/settings/save", what="maintenance", value="1")
        self.assertTrue(self.app.maintenance)
        self.assertEqual(self.db.get_setting("maintenance"), "1")
        self.post("/settings/save", what="maintenance", value="0")
        self.assertFalse(self.app.maintenance)
        self.assertEqual(self.db.get_setting("maintenance"), "0")

    def test_default_limits(self):
        self.post("/settings/save", what="limits", user="25", group="d")
        self.assertEqual(self.app.default_user_limit(), 25)
        self.assertEqual(self.db.get_setting("limit_group"), "")
        self.post("/settings/save", what="limits", user="7", group="d")            # invalid: nothing changes
        self.assertEqual(self.app.default_user_limit(), 25)

    def test_backup_is_sqlite(self):
        c = self.cookie
        import http.client
        from urllib.parse import urlencode
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/settings/backup", urlencode({"csrf": self.tok}),
                     {"Host": f"127.0.0.1:{self.port}", "Cookie": c, "Content-Type": "application/x-www-form-urlencoded"})
        r = conn.getresponse()
        data = r.read()
        self.assertEqual(r.status, 200)
        self.assertIn("attachment", r.getheader("Content-Disposition"))
        self.assertTrue(data.startswith(b"SQLite format 3"))
        conn.close()


class Broadcast(CtlBase):
    def wait_done(self):
        for _ in range(100):
            if not WebCtlMixin._bc_running:
                return
            time.sleep(0.05)
        self.fail("broadcast did not finish")

    def test_needs_confirmation_and_text(self):
        self.post("/settings/broadcast", text="hi")
        self.assertNotIn("web_broadcast", [a["action"] for a in self.db.list_audit(20)])
        self.post("/settings/broadcast", text="  ", confirm="1")
        self.assertNotIn("web_broadcast", [a["action"] for a in self.db.list_audit(20)])

    def test_sends_to_allowed_users_only_and_escapes(self):
        self.db.set_user(2, allowed=1)
        self.db.set_user(4, allowed=1, banned=1)                                  # banned: never messaged
        before = len(self.calls("sendMessage"))
        self.post("/settings/broadcast", text="<i>hello</i>", confirm="1")
        self.wait_done()
        sent = self.calls("sendMessage")[before:]
        targets = {p["chat_id"] for p in sent}
        self.assertIn(2, targets)
        self.assertNotIn(4, targets)
        self.assertNotIn(3, targets)                                              # only pressed /start / pending
        self.assertTrue(all("&lt;i&gt;hello&lt;/i&gt;" in p["text"] for p in sent))
        done = [a for a in self.db.list_audit(20) if a["action"] == "web_broadcast_done"]
        self.assertTrue(done)


class UserRoles(CtlBase):
    def test_promote_demote(self):
        self.post("/user/ctl", uid="2", act="promote")
        self.assertEqual(self.db.get_user(2)["role"], "mod")
        self.assertIn("سحب صفة المشرف", self.flash_of("/user?id=2"))
        self.post("/user/ctl", uid="2", act="demote")
        self.assertFalse(self.db.get_user(2).get("role"))

    def test_banned_not_promoted_and_admin_protected(self):
        self.db.set_user(2, banned=1)
        self.post("/user/ctl", uid="2", act="promote")
        self.assertFalse(self.db.get_user(2).get("role"))
        self.db.upsert_user(1, "boss", "Boss")
        self.post("/user/ctl", uid="1", act="demote")
        self.assertNotIn("صلاحيات متقدمة", self.flash_of("/user?id=1"))

    def test_clear_history_needs_confirmation(self):
        self.db.add_message(2, "user", "secret")
        self.post("/user/ctl", uid="2", act="clear")
        self.assertTrue(self.db.get_history(2))
        self.post("/user/ctl", uid="2", act="clear", confirm="1")
        self.assertFalse(self.db.get_history(2))


if __name__ == "__main__":
    unittest.main()


class Bulk(CtlBase):
    def test_bulk_approve_selected_skips_protected(self):
        self.post("/bulk", act="ap", ids="2,3,1", confirm="1", back="")
        self.assertEqual(self.db.get_user(2)["allowed"], 1)
        self.assertEqual(self.db.get_user(3)["allowed"], 1)
        self.assertIn("web_bulk_ap", [a["action"] for a in self.db.list_audit(20)])

    def test_bulk_needs_confirm_and_selection(self):
        self.post("/bulk", act="ban", ids="2", back="")
        self.assertEqual(self.db.get_user(2)["banned"], 0)
        self.post("/bulk", act="ban", confirm="1", back="")
        self.assertEqual(self.db.get_user(2)["banned"], 0)
        self.post("/bulk", act="drop", ids="2", confirm="1", back="")
        self.assertEqual(self.db.get_user(2)["banned"], 0)

    def test_bulk_scope_all_refuses_without_filter(self):
        self.post("/bulk", act="ban", scope="all", confirm="1", back="")
        self.assertEqual(self.db.get_user(2)["banned"], 0)

    def test_bulk_scope_all_uses_current_filter(self):
        self.post("/bulk", act="ap", scope="all", confirm="1", back="f=pending")
        self.assertEqual(self.db.get_user(3)["allowed"], 1)          # the only pending user
        self.assertEqual(self.db.get_user(2)["allowed"], 0)          # not in the filter

    def test_shell_and_checkbox_column(self):
        page = self.flash_of("/")
        self.assertIn('<body class="app">', page)
        self.assertIn('class="side"', page)
        self.assertIn('name="ids" value="2" form="bulk"', page)
        self.assertNotIn("<script", page)


class PythonCompat(unittest.TestCase):
    def test_no_backslash_inside_fstring_expressions(self):
        """requires-python is >=3.9: a backslash inside an f-string {expression} is a SyntaxError before 3.12."""
        import re
        for name in ("webui", "webctl", "webpanel", "webext", "webadmin"):
            with open(f"bot/{name}.py", encoding="utf-8") as fh:
                for n, line in enumerate(fh, 1):
                    if re.search(r"\bf['\"]", line):
                        self.assertIsNone(re.search(r"\{[^{}]*\\[^{}]*\}", line), f"{name}.py:{n}")


class LogsPage(CtlBase):
    def test_logs_page_scrubbed_and_escaped(self):
        import logging
        from bot.logsafe import RedactFilter
        from bot.ringlog import RING
        RING.clear()
        RING.addFilter(RedactFilter(["sk-test-SECRET-123456"]))
        root = logging.getLogger()
        root.addHandler(RING)                                                     # main.setup_logging does this in production
        try:
            logging.getLogger("bot.test").warning("key sk-test-SECRET-123456 <script>x</script>")
            logging.getLogger("bot.test").error("boom")
            page = self.flash_of("/logs")
            self.assertNotIn("SECRET-123456", page)
            self.assertNotIn("<script>x", page)
            self.assertIn("&lt;script&gt;", page)
            only_err = self.flash_of("/logs?l=ERROR")
            self.assertIn("boom", only_err)
            self.assertNotIn("&lt;script&gt;", only_err)
            self.assertEqual(self.req("GET", "/logs")[0], 303)                    # needs a session
        finally:
            root.removeHandler(RING)
            RING.filters.clear()
            RING.clear()


class Indexes(CtlBase):
    def test_panel_indexes_exist(self):
        names = {r[0] for r in self.db._conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        for n in ("idx_audit_ts", "idx_audit_user", "idx_users_seen", "idx_users_created", "idx_daily_day"):
            self.assertIn(n, names)
