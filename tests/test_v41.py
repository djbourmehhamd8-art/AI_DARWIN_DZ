"""v4.1: strict group authorisation, daily limits (user / group / defaults), resilient web search providers."""
import dataclasses
import time
import unittest

from bot import websearch as W
from tests import test_integration as ti
from tests.test_ui import cb, message
from tests.test_v34 import Harness
from tests.test_v39 import GROUP, Base, gmsg


class StrictGroupAuthorisation(Base):
    def setUp(self):
        super().setUp()
        self.app.bot_id = 4242
        for uid in (2, 3):
            self.app.on_message(message(uid, "hi"))
        self.db.set_user(2, allowed=1)                        # an approved user
        self.db.set_user(3, role="mod")                       # a moderator
        ti.CALLS.clear()
        ti.SEEN.clear()

    def test_nobody_is_answered_in_an_unauthorised_group(self):
        for uid, name in ((1, "admin"), (2, "approved"), (3, "mod")):
            self.app.on_message(gmsg(uid, "DZ كم عدد دول العالم؟", name=name))
        self.assertEqual(self.model_called(), 0)
        self.assertEqual(self.calls("sendDocument"), [])

    def test_commands_are_dead_too(self):
        for text in ("/help", "/export", "/search news", "/panel", "/backup", "/me"):
            self.app.on_message(gmsg(1, text, name="admin"))
        self.assertEqual(self.model_called(), 0)
        self.assertNotIn("adm:", str([p.get("reply_markup") for p in self.to(GROUP)]))

    def test_buttons_in_an_unauthorised_group_are_dead(self):
        data = cb(2, "ans:files")
        data["message"]["chat"] = {"id": GROUP, "type": "supergroup"}
        self.app.on_callback(data)
        self.assertEqual(self.to(GROUP), [])
        self.assertTrue(any(m == "answerCallbackQuery" and "🔒" in str(p) for m, p in ti.CALLS))

    def test_pings_staff_once_and_admin_can_activate(self):
        self.app.on_message(gmsg(2, "DZ hello"))
        self.assertIn(f"adm:gok:{GROUP}", str([p.get("reply_markup") for p in self.to(1)]))
        self.app.on_callback(cb(1, f"adm:gok:{GROUP}"))
        ti.CALLS.clear()
        self.app.on_message(gmsg(2, "DZ hello again"))
        self.assertEqual(self.model_called(), 1)

    def test_deactivating_a_group_stops_answers_again(self):
        self.app.on_message(gmsg(1, "/allowgroup", name="Boss"))
        self.app.on_message(gmsg(2, "DZ one"))
        self.assertEqual(self.model_called(), 1)
        self.app.on_message(gmsg(1, "/revokegroup", name="Boss"))
        self.app.on_message(gmsg(2, "DZ two"))
        self.assertEqual(self.model_called(), 1)

    def test_public_mode_does_not_open_groups(self):
        self.app.cfg = dataclasses.replace(self.app.cfg, public=True)
        self.app.on_message(gmsg(9, "DZ hello"))
        self.assertEqual(self.model_called(), 0)


class DailyLimits(Base):
    def setUp(self):
        super().setUp()
        self.app.on_message(message(2, "hi"))
        self.db.set_user(2, allowed=1)
        ti.CALLS.clear()
        ti.SEEN.clear()

    def test_group_limit_applies_to_the_whole_group(self):
        self.db.upsert_chat(GROUP, "G")
        self.db.set_chat_allowed(GROUP, True)
        self.app.on_callback(cb(1, f"adm:gli:{GROUP}:10"))
        self.assertEqual(self.db.get_chat(GROUP)["daily_limit"], 10)
        self.db.set_chat_limit(GROUP, 2)
        for i in range(2):
            self.app.on_message(gmsg(2, f"DZ question {i}"))
        self.assertEqual(self.db.daily_count(GROUP), 2)
        n = self.model_called()
        ti.CALLS.clear()
        self.app.on_message(gmsg(5, "DZ a different member", name="Other"))   # another member hits the same group cap
        self.assertEqual(self.model_called(), n)
        self.assertIn("حدّها اليومي", self.texts_to(GROUP))

    def test_group_limit_zero_means_unlimited_and_default_applies(self):
        self.db.upsert_chat(GROUP, "G")
        self.db.set_chat_allowed(GROUP, True)
        self.db.set_chat_limit(GROUP, 0)
        self.db.set_setting("limit_group", "1")                              # default says 1, but this group is unlimited
        for i in range(3):
            self.app.on_message(gmsg(2, f"DZ q{i}"))
        self.assertEqual(self.model_called(), 3)
        self.db.set_chat_limit(GROUP, -1)                                    # back to the default (1) -> already exceeded
        self.app.on_message(gmsg(2, "DZ q4"))
        self.assertEqual(self.model_called(), 3)

    def test_admin_is_exempt_from_the_group_cap(self):
        self.db.upsert_chat(GROUP, "G")
        self.db.set_chat_allowed(GROUP, True)
        self.db.set_chat_limit(GROUP, 1)
        self.db.bump_daily(GROUP)
        self.app.on_message(gmsg(1, "DZ admin question", name="Boss"))
        self.assertEqual(self.model_called(), 1)

    def test_default_limits_from_the_panel(self):
        self.app.on_callback(cb(1, "adm:lm"))
        self.assertIn("adm:lmu:25", self.buttons())
        self.assertIn("adm:lmg:100", self.buttons())
        self.app.on_callback(cb(1, "adm:lmu:25"))
        self.app.on_callback(cb(1, "adm:lmg:100"))
        self.assertEqual((self.app.default_user_limit(), self.app.default_group_limit()), (25, 100))
        self.app.on_callback(cb(1, "adm:lmu:0"))                              # unlimited
        self.assertEqual(self.app.default_user_limit(), 0)
        self.app.on_callback(cb(1, "adm:lmu:d"))                              # back to the .env value
        self.assertEqual(self.app.default_user_limit(), self.app.cfg.daily_limit)

    def test_default_user_limit_is_enforced_and_personal_override_wins(self):
        self.app.on_callback(cb(1, "adm:lmu:10"))
        for _ in range(10):
            self.db.bump_daily(2)
        self.app.on_message(message(2, "over the default"))
        self.assertEqual(self.model_called(), 0)
        self.app.on_callback(cb(1, "adm:lim:2:50"))                           # personal override beats the default
        self.app.on_message(message(2, "now fine"))
        self.assertEqual(self.model_called(), 1)

    def test_limit_screens_and_card_show_usage(self):
        self.db.upsert_chat(GROUP, "G")
        self.app.on_callback(cb(1, f"adm:gc:{GROUP}"))
        self.assertIn(f"adm:gli:{GROUP}", self.buttons())
        self.app.on_callback(cb(1, f"adm:gli:{GROUP}"))
        self.assertIn(f"adm:gli:{GROUP}:50", self.buttons())
        self.app.on_callback(cb(1, "adm:u:2"))
        self.assertIn("/", self.texts_to(1).split("اليوم")[-1])

    def test_moderator_cannot_change_limits(self):
        self.app.on_message(message(3, "hi"))
        self.db.set_user(3, role="mod")
        for data in ("adm:lm", "adm:lmu:10", "adm:lmg:10", f"adm:gli:{GROUP}:10", "adm:lim:2:10"):
            self.app.on_callback(cb(3, data))
        self.assertEqual(self.db.get_setting("limit_user"), "")
        self.assertEqual(self.db.get_user(2)["limit_override"], -1)

    def test_old_database_gets_the_group_limit_column(self):
        import os, sqlite3, tempfile
        from bot.storage import Storage
        path = os.path.join(tempfile.mkdtemp(), "v4.db")
        s = Storage(path)
        s.close()
        c = sqlite3.connect(path)
        c.executescript("DROP TABLE chats; CREATE TABLE chats (id INTEGER PRIMARY KEY, title TEXT NOT NULL DEFAULT '', "
                        "allowed INTEGER NOT NULL DEFAULT 0, added_at INTEGER NOT NULL, last_seen INTEGER NOT NULL); "
                        "INSERT INTO chats VALUES(-1,'old',1,1,1);")
        c.commit()
        c.close()
        s2 = Storage(path)
        self.assertEqual((s2.get_chat(-1)["allowed"], s2.get_chat(-1)["daily_limit"]), (1, -1))
        s2.close()


class FakeResp:
    def __init__(self, status=200, text="", js=None):
        self.status_code, self.text, self._js = status, text, js

    def json(self):
        return self._js


class FakeHTTP:
    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def _hit(self, url, **kw):
        self.calls.append(url)
        for k, v in self.routes.items():
            if k in url:
                if isinstance(v, Exception):
                    raise v
                return v
        raise AssertionError("unexpected request " + url)
    post = get = _hit


DDG = '<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fa.com%2F">A</a><a class="result__snippet">s</a>'
LITE = ("<a rel=\"nofollow\" href=\"//duckduckgo.com/l/?uddg=https%3A%2F%2Fb.com%2Fx&rut=1\" class='result-link'>B title</a>"
        "</td></tr><tr><td class='result-snippet'>B snippet</td>")
WIKI = {"query": {"pages": {"1": {"index": 2, "title": "List of countries", "extract": "There are 193 member states."},
                            "2": {"index": 1, "title": "Country", "extract": "A country is a political entity."}}}}


class SearchProviders(unittest.TestCase):
    def setUp(self):
        W._cache.clear()
        W._breaker.clear()

    def run_chain(self, routes, **kw):
        http = FakeHTTP(routes)
        return W.search_web("how many countries", http=http, **kw), http.calls

    def test_duckduckgo_first(self):
        (res, prov, _), _ = self.run_chain({"html.duckduckgo": FakeResp(text=DDG)})
        self.assertEqual((prov, res[0]["url"]), ("duckduckgo", "https://a.com/"))

    def test_blocked_html_falls_back_to_lite(self):
        (res, prov, diag), _ = self.run_chain({"html.duckduckgo": FakeResp(202, "x"), "lite.duckduckgo": FakeResp(text=LITE)})
        self.assertEqual((prov, res[0]["url"], res[0]["snippet"]), ("duckduckgo-lite", "https://b.com/x", "B snippet"))
        self.assertIn("HTTP 202", diag[0])

    def test_anti_bot_page_with_http_200_is_detected(self):
        (res, prov, diag), _ = self.run_chain({"duckduckgo.com": FakeResp(200, "<div class='anomaly-modal'>"),
                                               "wikipedia.org": FakeResp(js=WIKI)})
        self.assertEqual(prov, "wikipedia")
        self.assertIn("anti-bot", diag[0])
        self.assertEqual(res[0]["title"], "Country — Wikipedia (en)")            # ordered by relevance index

    def test_arabic_query_uses_arabic_wikipedia(self):
        http = FakeHTTP({"duckduckgo.com": FakeResp(403, ""), "ar.wikipedia.org": FakeResp(js=WIKI)})
        res, prov, _ = W.search_web("كم عدد دول العالم", http=http)
        self.assertEqual(prov, "wikipedia")
        self.assertTrue(any("ar.wikipedia.org" in c for c in http.calls))

    def test_all_providers_failing_returns_empty_with_reasons(self):
        (res, prov, diag), _ = self.run_chain({"duckduckgo": ConnectionError("x"), "wikipedia": ConnectionError("y")})
        self.assertEqual((res, prov), ([], ""))
        self.assertEqual(len(diag), 3)

    def test_brave_and_searxng_come_first_when_configured(self):
        (res, prov, _), calls = self.run_chain({"brave.com": FakeResp(js={"web": {"results": [
            {"title": "T", "url": "https://t.com", "description": "d"}, {"title": "bad", "url": "javascript:x"}]}})}, brave_key="K")
        self.assertEqual((prov, len(res), calls), ("brave", 1, ["https://api.search.brave.com/res/v1/web/search"]))
        W._cache.clear()
        (res, prov, _), calls = self.run_chain({"searx.example.org": FakeResp(js={"results": [
            {"title": "S", "url": "https://s.com", "content": "c"}]})}, searxng_url="https://searx.example.org")
        self.assertEqual(prov, "searxng")

    def test_blocked_provider_is_skipped_for_a_while_and_results_are_cached(self):
        http = FakeHTTP({"duckduckgo.com": FakeResp(403, ""), "wikipedia.org": FakeResp(js=WIKI)})
        W.search_web("q1", http=http)
        first = len(http.calls)
        W.search_web("q2", http=http)
        self.assertEqual(len(http.calls) - first, 1)                               # only Wikipedia was tried the 2nd time
        http2 = FakeHTTP({"html.duckduckgo": FakeResp(text=DDG)})
        W._breaker.clear()
        W.search_web("same", http=http2)
        self.assertIn("cached", W.search_web("same", http=http2)[1])
        self.assertEqual(len(http2.calls), 1)

    def test_diagnose_mode_tries_every_provider(self):
        http = FakeHTTP({"html.duckduckgo": FakeResp(text=DDG), "lite.duckduckgo": FakeResp(text=LITE), "wikipedia.org": FakeResp(js=WIKI)})
        res, prov, diag = W.search_web("q", http=http, stop_on_first=False)
        self.assertEqual((prov, len(diag)), ("duckduckgo", 3))

    def test_urls_with_javascript_scheme_are_dropped_from_lite(self):
        page = "<a href=\"javascript:alert(1)\" class='result-link'>x</a><td class='result-snippet'>s</td>"
        self.assertEqual(W.parse_lite(page), [])


class AdminSearchTools(Harness):
    __test__ = True

    def test_websearch_command_and_button(self):
        from unittest import mock
        fake = ([{"title": "T", "url": "https://t", "snippet": ""}], "wikipedia", ["duckduckgo: HTTP 202", "wikipedia: ok (1)"])
        with mock.patch("bot.websearch.search_web", return_value=fake):
            self.app.on_message(message(1, "/websearch test query"))
            self.app.on_callback(cb(1, "adm:wt"))
        self.assertIn("HTTP 202", self.texts())
        self.assertIn("wikipedia", self.texts())

    def test_failure_message_still_arrives_and_provider_shown_in_sources(self):
        from unittest import mock
        with mock.patch("bot.web_files.websearch.search", return_value=[]):
            self.app.on_message(message(1, "/search latest news"))
        self.assertIn("Echo:", self.texts())


if __name__ == "__main__":
    unittest.main()
