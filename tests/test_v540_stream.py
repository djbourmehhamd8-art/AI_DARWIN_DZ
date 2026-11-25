import json
import unittest
from unittest import mock

from tests.test_webchat import ChatBase


def _lines(body: str) -> list:
    return [json.loads(x) for x in body.splitlines() if x.strip()]


class Streaming(ChatBase):
    def _fake(self, parts, final):
        def chat(msgs, temp=0.7, stream=True, on_delta=None):
            assert stream is True and on_delta is not None
            for p in parts:
                on_delta(p)
            return final, {}
        return chat

    def test_stream_emits_deltas_then_done_and_stores_history(self):
        cookie, csrf = self.login()
        with mock.patch.object(self.app.ai, "chat", side_effect=self._fake(["he", "hello", "hello wor"], "hello world")):
            st, hd, body = self.req("POST", "/api/chat", {"msg": "hi", "stream": True}, cookie=cookie, csrf=csrf)
        self.assertEqual(st, 200)
        self.assertIn("ndjson", hd.get("Content-Type", ""))
        self.assertEqual(hd.get("Connection", "").lower(), "close")
        self.assertEqual(_lines(body), [{"t": "he"}, {"t": "llo"}, {"t": " wor"}, {"done": True, "reply": "hello world"}])
        key = cookie.split("=", 1)[1]
        self.assertEqual([m["content"] for m in self.site.sessions[key]["chat"]], ["hi", "hello world"])

    def test_restarted_answer_sends_reset(self):
        cookie, csrf = self.login()
        with mock.patch.object(self.app.ai, "chat", side_effect=self._fake(["abc", "xy", "xyz"], "xyz")):
            _, _, body = self.req("POST", "/api/chat", {"msg": "hi", "stream": True}, cookie=cookie, csrf=csrf)
        self.assertEqual(_lines(body), [{"t": "abc"}, {"reset": True}, {"t": "xy"}, {"t": "z"}, {"done": True, "reply": "xyz"}])

    def test_errors_before_first_token_are_plain_json(self):
        cookie, csrf = self.login()
        st, hd, body = self.req("POST", "/api/chat", {"msg": "   ", "stream": True}, cookie=cookie, csrf=csrf)
        self.assertEqual(st, 400)
        self.assertIn("application/json", hd.get("Content-Type", ""))
        self.assertIn("error", json.loads(body))

    def test_error_after_first_token_is_reported_in_the_stream(self):
        from bot.ai_client import APIError
        cookie, csrf = self.login()

        def boom(msgs, temp=0.7, stream=True, on_delta=None):
            on_delta("partial")
            raise APIError(500, "upstream")
        with mock.patch.object(self.app.ai, "chat", side_effect=boom):
            _, _, body = self.req("POST", "/api/chat", {"msg": "hi", "stream": True}, cookie=cookie, csrf=csrf)
        rows = _lines(body)
        self.assertEqual(rows[0], {"t": "partial"})
        self.assertIn("error", rows[-1])
        self.assertEqual(self.site.sessions[cookie.split("=", 1)[1]]["chat"], [])        # nothing half-saved

    def test_regenerate_can_stream_too(self):
        cookie, csrf = self.login()
        with mock.patch.object(self.app.ai, "chat", side_effect=[("one", {}), ("two", {})]):
            self.req("POST", "/api/chat", {"msg": "q"}, cookie=cookie, csrf=csrf)
            st, _, body = self.req("POST", "/api/regenerate", {"stream": True}, cookie=cookie, csrf=csrf)
        self.assertEqual(st, 200)
        self.assertIn("two", body)                                                          # non-streaming client library: plain JSON fallback

    def test_microphone_is_allowed_for_the_page_itself(self):
        cookie, _ = self.login()
        _, hd, _ = self.req("GET", "/", cookie=cookie)
        self.assertIn("microphone=(self)", hd["Permissions-Policy"])


if __name__ == "__main__":
    unittest.main()
