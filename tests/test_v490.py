"""v4.9.0: problem reports (bot + storage) and the admin web panel v2 (overview, reports inbox, user page, audit search)."""
import re
import time
import unittest
from urllib.parse import urlencode

from bot import __version__
from bot.storage import Storage
from bot.webadmin import bar_chart, safe_ret
from tests import test_integration as ti
from tests.test_ui import cb, message
from tests.test_v34 import Harness
from tests.test_v440 import TOKEN, PanelBase


def sent_to(uid):
    return "\n".join(p.get("text", "") for m, p in ti.CALLS if m in ("sendMessage", "editMessageText") and p.get("chat_id") == uid)


class ReportStorage(unittest.TestCase):
    def setUp(self):
        self.db = Storage(":memory:")
        self.db.upsert_user(5, "bob", "Bob")

    def test_lifecycle_and_counts(self):
        rid = self.db.add_report(5, "bug", "it broke", "v1")
        self.assertEqual(self.db.report_counts(), {"open": 1, "closed": 0, "all": 1})
        self.assertEqual(self.db.get_report(rid)["username"], "bob")
        self.assertTrue(self.db.set_report(rid, status="closed", reply="fixed"))
        self.assertEqual(self.db.report_counts()["closed"], 1)
        self.assertEqual(self.db.get_report(rid)["reply"], "fixed")
        self.assertTrue(self.db.delete_report(rid))
        self.assertFalse(self.db.delete_report(rid))

    def test_unknown_kind_falls_back_and_text_is_bounded(self):
        rid = self.db.add_report(5, "<script>", "x" * 5000)
        r = self.db.get_report(rid)
        self.assertEqual(r["kind"], "other")
        self.assertEqual(len(r["text"]), 2000)

    def test_search_treats_wildcards_literally_and_filters(self):
        self.db.add_report(5, "bug", "plain text")
        self.db.add_report(5, "idea", "100% broken_thing")
        self.assertEqual(self.db.list_reports(q="%")[1], 1)
        self.assertEqual(self.db.list_reports(q="_")[1], 1)
        self.assertEqual(self.db.list_reports(kind="idea")[1], 1)
        self.assertEqual(self.db.list_reports(q="bob")[1], 2)
        self.assertEqual(self.db.list_reports(q="5")[1], 2)

    def test_open_first_ordering_and_user_limits(self):
        a = self.db.add_report(5, "bug", "first")
        self.db.add_report(5, "bug", "second")
        self.db.set_report(a + 1, status="closed")
        self.assertEqual(self.db.list_reports()[0][0]["status"], "open")
        self.assertEqual(self.db.reports_since(5), 2)
        self.assertEqual(self.db.open_reports_of(5), 1)

    def test_overview_series_are_zero_filled(self):
        self.db.bump_daily(5)
        s = self.db.messages_series(14)
        self.assertEqual(len(s), 14)
        self.assertEqual(s[-1][1:], (1, 1))
        self.assertEqual(len(self.db.signups_series(14)), 14)
        self.assertEqual(self.db.overview_numbers()["active24"], 1)
        self.assertEqual(len(self.db.user_daily(5, 7)), 7)

    def test_audit_search(self):
        self.db.add_audit(0, "web_ban", "5:")
        self.db.add_audit(5, "deny", "x")
        self.assertEqual(self.db.search_audit(action="web")[1], 1)
        self.assertEqual(self.db.search_audit(q="5")[1], 2)
        self.assertEqual(self.db.search_audit(q="%")[1], 0)
        self.assertIn("web", self.db.audit_actions())


class BotReports(Harness):
    __test__ = True

    def setUp(self):
        super().setUp()
        self.db.upsert_user(1, "admin", "Admin")
        self.db.upsert_user(2, "alice", "Alice")
        self.db.set_user(2, allowed=1)

    def test_menu_then_button_flow_files_a_report_and_alerts_admin(self):
        self.app.on_message(message(2, "/problem"))
        self.assertIn("rp:new:bug", self.buttons())
        self.app.on_callback(cb(2, "rp:new:tool"))
        self.app.on_message(message(2, "The hash tool gave a wrong result for empty input"))
        r = self.db.list_reports()[0][0]
        self.assertEqual((r["user_id"], r["kind"]), (2, "tool"))
        self.assertIn(__version__, r["ctx"])
        self.assertIn(f"#{r['id']}", sent_to(2))
        self.assertIn("wrong result", sent_to(1))                      # admin was alerted
        self.assertIn(f"rp:reply:{r['id']}", self.buttons())

    def test_inline_text_and_validation(self):
        self.app.on_message(message(2, "/problem it crashes when I press menu twice"))
        self.assertEqual(self.db.report_counts()["open"], 1)
        self.app.on_message(message(2, "/bug hi"))                      # too short
        self.assertEqual(self.db.report_counts()["open"], 1)

    def test_limits_and_duplicates(self):
        for i in range(7):
            self.app.on_message(message(2, f"/problem problem number {i} is here"))
        self.assertEqual(self.db.report_counts()["open"], 5)            # MAX_PER_DAY
        n = self.db.report_counts()["open"]
        self.app.on_message(message(2, "/problem problem number 0 is here"))
        self.assertEqual(self.db.report_counts()["open"], n)

    def test_last_tool_is_attached(self):
        self.app.on_message(message(2, "/chmod 755"))
        self.app.on_message(message(2, "/problem the chmod answer looks odd"))
        self.assertIn("chmod", self.db.list_reports()[0][0]["ctx"])

    def test_group_chat_is_refused(self):
        self.app.cmd_problem(-100123, {"id": 2, "lang": "en"}, "something is broken in the group")
        self.assertEqual(self.db.report_counts()["open"], 0)
        self.assertIn("private chat", self.texts())

    def test_admin_triage_reply_and_close_reaches_user(self):
        self.app.on_message(message(2, "/problem please look at the failing tool"))
        rid = self.db.list_reports()[0][0]["id"]
        self.app.on_message(message(1, "/reports"))
        self.assertIn(f"rp:view:{rid}", self.buttons())
        self.app.on_callback(cb(1, f"rp:reply:{rid}"))
        self.app.on_message(message(1, "Fixed in the next version, thanks!"))
        r = self.db.get_report(rid)
        self.assertEqual((r["status"], r["reply"]), ("closed", "Fixed in the next version, thanks!"))
        self.assertIn("Fixed in the next version", sent_to(2))
        self.app.on_message(message(2, "/myreports"))
        self.assertIn("مُغلق", sent_to(2))

    def test_replyreport_command_and_reopen(self):
        self.app.on_message(message(2, "/problem the thing is broken again"))
        rid = self.db.list_reports()[0][0]["id"]
        self.app.on_message(message(1, f"/replyreport {rid} we are on it"))
        self.assertEqual(self.db.get_report(rid)["status"], "closed")
        self.app.on_callback(cb(1, f"rp:open:{rid}"))
        self.assertEqual(self.db.get_report(rid)["status"], "open")

    def test_non_admin_cannot_triage(self):
        self.app.on_message(message(2, "/problem my own report about a bug"))
        rid = self.db.list_reports()[0][0]["id"]
        for action in ("close", "reply", "del", "delyes", "view", "list"):
            self.app.on_callback(cb(2, f"rp:{action}:{rid}"))
        self.assertEqual(self.db.get_report(rid)["status"], "open")
        self.assertIsNotNone(self.db.get_report(rid))
        self.app.on_message(message(2, "/reports"))
        self.assertEqual(self.db.get_report(rid)["status"], "open")

    def test_delete_needs_confirmation(self):
        self.app.on_message(message(2, "/problem delete me please, it is a test"))
        rid = self.db.list_reports()[0][0]["id"]
        self.app.on_callback(cb(1, f"rp:del:{rid}"))
        self.assertIsNotNone(self.db.get_report(rid))
        self.app.on_callback(cb(1, f"rp:delyes:{rid}"))
        self.assertIsNone(self.db.get_report(rid))

    def test_slash_report_is_still_the_case_report_command(self):
        self.app.on_message(message(1, "/report"))
        self.assertNotIn("rp:new:bug", self.buttons())
        self.assertIn("لا توجد محادثة", self.texts())                 # the pre-existing meaning: AI report from the case history
        self.assertEqual(self.app.commands["report"].__func__.__qualname__.split(".")[0] != "ReportsMixin", True)

    def test_main_menu_has_report_button(self):
        self.app.on_message(message(2, "/menu"))
        self.assertIn("rp:menu", self.buttons())


class NoSilentShadowing(unittest.TestCase):
    """A method defined in two mixins means one silently hides the other (that is how /report almost got broken)."""
    KNOWN: dict = {}                                    # no accepted overrides: a clash is always a bug (dead copies of cmd_cve/cmd_save were removed in 5.3.0)

    def test_mixins_do_not_override_each_other_by_accident(self):
        from collections import defaultdict
        from bot.handlers import BotApp
        seen = defaultdict(list)
        for c in BotApp.__mro__:
            if c in (object, BotApp):
                continue
            for n, v in c.__dict__.items():
                if callable(v) and not n.startswith("__"):
                    seen[n].append(c.__name__)
        clashes = {n: cs for n, cs in seen.items() if len(cs) > 1 and n not in self.KNOWN}
        self.assertEqual(clashes, {}, "a mixin method hides another one; rename it or list it in KNOWN with the reason")


class Helpers(unittest.TestCase):
    def test_safe_ret_blocks_open_redirects(self):
        for ok in ("/overview", "/reports", "/user?id=123", "/reports?f=open&q=abc"):
            self.assertEqual(safe_ret(ok), ok)
        for bad in ("http://evil.com", "//evil.com", "/user?id=abc", "/user?id=1&x=2", "/\\evil", "javascript:alert(1)", "/reports?<script>"):
            self.assertEqual(safe_ret(bad), "", bad)

    def test_bar_chart_scales_and_escapes(self):
        html_ = bar_chart([("2026-01-01", 10), ("2026-01-02", 0), ("<b>", 5)])
        self.assertIn("height:100%", html_)
        self.assertNotIn("<b>:", html_)


class AdminWeb(PanelBase):
    def get(self, cookie, path):
        return self.req("GET", path, cookie=cookie)

    def post(self, cookie, path, body):
        return self.req("POST", path, {"csrf": self.csrf(cookie), **body}, cookie=cookie)

    def setUp(self):
        super().setUp()
        self.db.set_user(2, allowed=1)
        self.rid = self.db.add_report(2, "bug", "<script>alert(1)</script> broken", "v-test")

    def test_all_new_pages_require_login(self):
        for path in ("/overview", "/reports", "/reports.csv", "/user?id=2", "/audit.csv"):
            st, hd, _ = self.get("", path)
            self.assertEqual(st, 303, path)

    def test_overview_renders_numbers_and_badge(self):
        c = self.login()
        st, _, page = self.get(c, "/overview")
        self.assertEqual(st, 200)
        for needle in ("نظرة عامة", "بلاغات مفتوحة", "chart", "طلبات معلّقة", 'href="/reports"'):
            self.assertIn(needle, page)
        self.assertRegex(page, r"📨 البلاغات</span><span class=\"b bad\">1</span>")

    def test_reports_page_escapes_and_filters(self):
        c = self.login()
        page = self.get(c, "/reports")[2]
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("<script>alert(1)", page)
        self.assertIn(f'id="r{self.rid}"', page)
        self.assertNotIn(f'id="r{self.rid}"', self.get(c, "/reports?f=closed")[2])
        self.assertIn(f'id="r{self.rid}"', self.get(c, "/reports?q=alice&f=all")[2])
        self.assertNotIn(f'id="r{self.rid}"', self.get(c, "/reports?k=idea")[2])

    def test_reply_and_close_sends_telegram_message(self):
        c = self.login()
        ti.CALLS.clear()
        st, hd, _ = self.post(c, "/reports/act", {"rid": self.rid, "act": "reply_close", "reply": "Thanks, fixed!", "back": "f=open"})
        self.assertEqual(st, 303)
        self.assertTrue(hd["Location"].startswith("/reports"))
        r = self.db.get_report(self.rid)
        self.assertEqual((r["status"], r["reply"]), ("closed", "Thanks, fixed!"))
        self.assertIn("Thanks, fixed!", sent_to(2))
        self.assertTrue(any(a["action"] == "report_reply" for a in self.db.list_audit(5)))

    def test_empty_reply_and_unconfirmed_delete_do_nothing(self):
        c = self.login()
        self.post(c, "/reports/act", {"rid": self.rid, "act": "reply", "reply": "  "})
        self.assertEqual(self.db.get_report(self.rid)["reply"], "")
        self.post(c, "/reports/act", {"rid": self.rid, "act": "delete"})
        self.assertIsNotNone(self.db.get_report(self.rid))
        self.post(c, "/reports/act", {"rid": self.rid, "act": "delete", "confirm": "1"})
        self.assertIsNone(self.db.get_report(self.rid))

    def test_close_open_toggle(self):
        c = self.login()
        self.post(c, "/reports/act", {"rid": self.rid, "act": "close"})
        self.assertEqual(self.db.get_report(self.rid)["status"], "closed")
        self.post(c, "/reports/act", {"rid": self.rid, "act": "open"})
        self.assertEqual(self.db.get_report(self.rid)["status"], "open")

    def test_post_requires_csrf(self):
        c = self.login()
        st, _, _ = self.req("POST", "/reports/act", {"rid": self.rid, "act": "close", "csrf": "wrong"}, cookie=c)
        self.assertEqual(st, 403)
        st, _, _ = self.req("POST", "/user/dm", {"uid": 2, "text": "hi", "csrf": "wrong"}, cookie=c)
        self.assertEqual(st, 403)
        self.assertEqual(self.db.get_report(self.rid)["status"], "open")

    def test_reports_csv_neutralises_formulas(self):
        self.db.add_report(2, "other", "=HYPERLINK(\"http://x\")")
        c = self.login()
        st, hd, body = self.get(c, "/reports.csv?f=all")
        self.assertEqual(st, 200)
        self.assertIn("text/csv", hd["Content-Type"])
        self.assertNotRegex(body, r",=HYPERLINK")

    def test_user_page_and_actions_return_to_it(self):
        c = self.login()
        page = self.get(c, "/user?id=2")[2]
        self.assertIn("alice", page)
        self.assertIn("/user/dm", page)
        self.assertIn(f"#{self.rid}", page)
        st, hd, _ = self.post(c, "/act", {"uid": 2, "act": "ban", "ret": "/user?id=2"})
        self.assertEqual((st, hd["Location"]), (303, "/user?id=2"))
        self.assertEqual(self.db.get_user(2)["banned"], 1)
        st, hd, _ = self.post(c, "/act", {"uid": 2, "act": "ub", "ret": "http://evil.example"})
        self.assertTrue(hd["Location"].startswith("/?"))                # unsafe return target ignored
        self.assertIn("غير موجود", self.get(c, "/user?id=999999")[2])
        self.assertEqual(self.get(c, "/user?id=abc")[0], 200)

    def test_user_page_protects_admins(self):
        c = self.login()
        self.db.upsert_user(1, "boss", "Boss")
        self.assertIn("محمي", self.get(c, "/user?id=1")[2])

    def test_direct_message_to_user(self):
        c = self.login()
        ti.CALLS.clear()
        self.post(c, "/user/dm", {"uid": 2, "text": "Hello from the admins"})
        self.assertIn("Hello from the admins", sent_to(2))
        self.assertTrue(any(a["action"] == "web_dm" for a in self.db.list_audit(5)))
        before = len(ti.CALLS)
        self.post(c, "/user/dm", {"uid": 424242, "text": "x"})
        self.assertEqual(len(ti.CALLS), before)

    def test_audit_search_filter_pagination_and_csv(self):
        for i in range(120):
            self.db.add_audit(0, "web_test", f"n{i}")
        self.db.add_audit(9, "deny", "needle-here")
        c = self.login()
        page = self.get(c, "/audit?q=needle")[2]
        self.assertIn("needle-here", page)
        self.assertNotIn("n7<", page)
        self.assertIn("صفحة 1 من 3", self.get(c, "/audit?a=web")[2])
        self.assertIn("n0", self.get(c, "/audit?a=web&p=3")[2])
        st, hd, body = self.get(c, "/audit.csv?q=needle")
        self.assertEqual(st, 200)
        self.assertIn("needle-here", body)

    def test_users_table_links_to_detail(self):
        c = self.login()
        self.assertIn('href="/user?id=2"', self.get(c, "/")[2])

    def test_quick_approve_from_overview(self):
        c = self.login()
        st, hd, _ = self.post(c, "/act", {"uid": 3, "act": "ap", "ret": "/overview"})
        self.assertEqual((st, hd["Location"]), (303, "/overview"))
        self.assertEqual(self.db.get_user(3)["allowed"], 1)

    def test_hostile_query_strings_never_cause_a_500(self):
        c = self.login()
        evil = ["p=-5", "p=99999999999999999999", "f=%3Cscript%3E", "q=%00%00", "q=" + "a" * 5000, "k=../../x", "id=-1", "id=" + "9" * 40,
                "a=%27%3B--", "o=zzz&s=zzz", "q=%25%5F%25", "p=abc&f=all&k=bug"]
        for path in ("/reports", "/user", "/audit", "/audit.csv", "/reports.csv", "/overview", "/"):
            for qs in evil:
                st = self.get(c, f"{path}?{qs}")[0]
                self.assertIn(st, (200, 303, 414), f"{path}?{qs[:30]} -> {st}")

    def test_nav_has_new_tabs_everywhere(self):
        c = self.login()
        for path in ("/", "/tools", "/audit", "/system", "/reports", "/overview"):
            page = self.get(c, path)[2]
            self.assertIn('href="/overview"', page, path)
            self.assertIn('href="/reports"', page, path)


if __name__ == "__main__":
    unittest.main()
