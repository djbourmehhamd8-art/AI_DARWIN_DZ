"""v3.7: web-grounded answers, safe fetching, file export (ZIP/TXT/MD/HTML/JSON/CSV/code), expert mode."""
import io
import unittest
import zipfile
from unittest import mock

from bot import files as F
from bot import websearch as W
from bot.brand import CORE_PROMPT, DETAIL_PROMPTS
from tests import test_integration as ti
from tests.test_ui import cb, message
from tests.test_v34 import Harness

ANSWER = """الحل:

**app/main.py**
```python
print("hi")
```
**requirements.txt**
```
requests==2.32.0
```

| name | score |
|------|-------|
| a | 1 |
"""


class SearchUnits(unittest.TestCase):
    def test_parse_results_skips_ads_and_decodes(self):
        page = ('<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fa&amp;rut=1">Ex &amp; Co</a>'
                '<a class="result__snippet" href="x">Great <b>text</b></a>'
                '<a class="result__a" href="https://duckduckgo.com/y.js?ad=1">Ad</a>')
        r = W.parse_results(page)
        self.assertEqual(r, [{"title": "Ex & Co", "url": "https://example.com/a", "snippet": "Great text"}])

    def test_should_search_modes(self):
        self.assertTrue(W.should_search("ما هو آخر إصدار من nginx", "auto"))
        self.assertTrue(W.should_search("latest CVE-2024-3094 details", "auto"))
        self.assertFalse(W.should_search("اشرح الفرق بين TCP و UDP", "auto"))
        self.assertTrue(W.should_search("اشرح الفرق بين TCP و UDP", "on"))
        self.assertFalse(W.should_search("latest news", "off"))
        self.assertFalse(W.should_search("/start now", "on"))

    def test_ssrf_guard(self):
        for url in ("http://127.0.0.1/", "http://169.254.169.254/latest/meta-data", "file:///etc/passwd",
                    "http://localhost:8080/", "http://user:pw@example.com/", "https://[::1]/", "http://10.0.0.5/",
                    "ftp://example.com/", "http://example.com:22/"):
            self.assertFalse(W.is_safe_url(url), url)

    def test_fetch_refuses_private_redirect(self):
        calls = []

        class R:
            status_code = 302
            headers = {"Location": "http://169.254.169.254/x"}
            encoding = "utf-8"

            def close(self):
                pass

        def fake_get(url, **kw):
            calls.append((url, kw["ip"]))
            return R()
        resolve = lambda h: "93.184.216.34" if h == "example.com" else None          # noqa: E731
        self.assertEqual(W.fetch_text("https://example.com/a", get=fake_get, resolve=resolve), "")
        self.assertEqual(calls, [("https://example.com/a", "93.184.216.34")])     # the private hop was never requested

    def test_html_to_text(self):
        t = W.html_to_text("<head><title>x</title></head><script>evil()</script><p>Hello &amp; bye</p><style>a{}</style>")
        self.assertEqual(t, "Hello & bye")

    def test_context_marks_untrusted(self):
        c = W.build_context([{"title": "T", "url": "https://e.com", "snippet": "S"}], {}, "2026-11-02")
        self.assertIn("untrusted", c)
        self.assertIn("[1] T", c)


class FileUnits(unittest.TestCase):
    def test_extract_names(self):
        files = F.extract_files(ANSWER)
        self.assertEqual([n for n, _ in files], ["app/main.py", "requirements.txt"])

    def test_path_traversal_blocked(self):
        for bad in ("../../etc/passwd", "/abs/path.py", "..\\..\\win.ini", "a/../../b.txt"):
            n = F.safe_name(bad)
            self.assertFalse(n.startswith("/") or ".." in n.split("/"), n)

    def test_zip_contents_and_limits(self):
        data = F.make_zip(F.extract_files(ANSWER), ANSWER)
        names = zipfile.ZipFile(io.BytesIO(data)).namelist()
        self.assertEqual(names, ["app/main.py", "requirements.txt", "ANSWER.md"])
        with self.assertRaises(ValueError):
            F.make_zip([(f"f{i}.txt", "x") for i in range(F.MAX_FILES + 1)])
        with self.assertRaises(ValueError):
            F.make_zip([("big.txt", "x" * (F.MAX_TOTAL + 1))])

    def test_csv_and_plain_and_html(self):
        self.assertIn(b"name,score", F.first_table_csv(ANSWER))
        self.assertIsNone(F.first_table_csv("no table here"))
        self.assertNotIn("```", F.to_plain(ANSWER))
        page = F.to_html_page("x", "<b>ok</b>").decode()
        self.assertNotIn("<script", page)

    def test_duplicate_names_get_suffix(self):
        t = "```python title=a.py\n1\n```\n```python title=a.py\n2\n```"
        self.assertEqual([n for n, _ in F.extract_files(t)], ["a.py", "a_2.py"])


class Prompts(unittest.TestCase):
    def test_prompt_blocks(self):
        self.assertIn("DEPTH AND COMPLETENESS", CORE_PROMPT)
        self.assertIn("CODE AND FILES", CORE_PROMPT)
        self.assertIn("expert", DETAIL_PROMPTS)


class WebAnswers(Harness):
    __test__ = True

    FAKE = [{"title": "Nginx release", "url": "https://nginx.org/en/CHANGES", "snippet": "nginx 1.27 released"}]

    def run_msg(self, text):
        with mock.patch("bot.web_files.websearch.search", return_value=self.FAKE), \
                mock.patch("bot.web_files.websearch.fetch_text", return_value="page body about nginx 1.27"):
            self.app.on_message(message(1, text))

    def test_auto_mode_searches_and_cites(self):
        self.run_msg("ما هو آخر إصدار من nginx")
        system = ti.SEEN[-1][0]["content"]
        self.assertIn("retrieved just now", system)
        self.assertIn("page body about nginx", system)
        self.assertIn("🔗", self.texts())
        self.assertIn("nginx.org", self.texts())

    def test_plain_question_does_not_search(self):
        self.run_msg("اشرح الفرق بين TCP و UDP")
        self.assertNotIn("retrieved just now", ti.SEEN[-1][0]["content"])

    def test_off_mode_never_searches(self):
        self.app.on_message(message(1, "/web off"))
        self.run_msg("ما هو آخر إصدار من nginx")
        self.assertNotIn("retrieved just now", ti.SEEN[-1][0]["content"])

    def test_search_command_forces(self):
        with mock.patch("bot.web_files.websearch.search", return_value=self.FAKE) as s, \
                mock.patch("bot.web_files.websearch.fetch_text", return_value=""):
            self.app.on_message(message(1, "/search اشرح TCP"))
        self.assertTrue(s.called)
        self.assertIn("retrieved just now", ti.SEEN[-1][0]["content"])

    def test_failure_falls_back(self):
        with mock.patch("bot.web_files.websearch.search", return_value=[]):
            self.app.on_message(message(1, "/search latest news about openssl"))
        self.assertIn("Echo:", self.texts())                            # the answer still arrives

    def test_secrets_not_sent_to_search(self):
        q = self.app._web_query("find AWS key AKIAIOSFODNN7EXAMPLE usage")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", q)

    def test_web_buttons(self):
        self.app.on_callback(cb(1, "m:web"))
        for need in ("web:off", "web:auto", "web:on"):
            self.assertIn(need, self.buttons())
        self.app.on_callback(cb(1, "web:on"))
        self.assertEqual(self.db.get_user(1)["web"], "on")


class FileExports(Harness):
    __test__ = True

    def setUp(self):
        super().setUp()
        self.app.on_message(message(1, "hi"))                           # creates the user row
        self.db.add_message(1, "user", "write code")
        self.db.add_message(1, "assistant", ANSWER)

    def test_every_format_sends_a_document(self):
        for fmt in ("txt", "md", "html", "json", "csv", "zip", "code"):
            ti.CALLS.clear()
            self.app.on_callback(cb(1, f"fx:{fmt}"))
            self.assertTrue(self.calls("sendDocument"), fmt)

    def test_menu_and_answer_buttons(self):
        self.app.on_callback(cb(1, "m:files"))
        for need in ("fx:zip", "fx:txt", "fx:html", "fx:json", "fx:csv", "fx:code", "fx:md"):
            self.assertIn(need, self.buttons())

    def test_save_command(self):
        ti.CALLS.clear()
        self.app.on_message(message(1, "/save ../../evil.py print(1)"))
        self.assertTrue(self.calls("sendDocument"))

    def test_zip_command_without_answer(self):
        self.db.clear_history(1)
        ti.CALLS.clear()
        self.app.on_message(message(1, "/zip"))
        self.assertFalse(self.calls("sendDocument"))


if __name__ == "__main__":
    unittest.main()
