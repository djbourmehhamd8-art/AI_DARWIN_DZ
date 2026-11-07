from __future__ import annotations

import logging
import threading
import time

import requests

log = logging.getLogger("bot.telegram")


class TelegramAPI:
    def __init__(self, token: str, base_url: str = "https://api.telegram.org"):
        self.base = f"{base_url}/bot{token}"
        self.file_base = f"{base_url}/file/bot{token}"
        self.session = requests.Session()
        self.poll_error = None                   # (error_code, description) of the last failed getUpdates
        self.styles_ok = True                    # False once a server rejects button colours
        self._tl = threading.local()
        adapter = requests.adapters.HTTPAdapter(pool_connections=4, pool_maxsize=32)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def call(self, method: str, timeout: float = 30, files=None, **params):
        """Call a Bot API method with bounded retries and defensive response parsing."""
        params = {k: v for k, v in params.items() if v is not None}
        for attempt in range(4):
            response = None
            try:
                url = f"{self.base}/{method}"
                if files:
                    response = self.session.post(url, data=params, files=files, timeout=timeout)
                else:
                    response = self.session.post(url, json=params, timeout=timeout)
                data = response.json()
                if not isinstance(data, dict):
                    raise ValueError("Telegram returned a non-object JSON response")
            except requests.RequestException as e:
                log.warning("%s failed: %s", method, e)
                if attempt < 3:
                    time.sleep(1 + attempt)
                continue
            except ValueError as e:
                log.warning("%s returned an invalid response: %s", method, e)
                return None
            finally:
                if response is not None:
                    response.close()
            if data.get("ok") is True:
                return data.get("result")
            if data.get("error_code") == 429:
                raw_wait = (data.get("parameters") or {}).get("retry_after", 2)
                try:
                    wait = max(0.0, min(float(raw_wait), 29.5))
                except (TypeError, ValueError):
                    wait = 2.0
                log.warning("flood wait %.1fs on %s", wait, method)
                if attempt < 3:
                    time.sleep(wait + 0.5)
                continue
            desc = str(data.get("description", ""))[:300]
            if "not modified" in desc.lower():
                return True
            log.warning("%s error: %s", method, desc)
            self._tl.last_error = desc
            return None
        return None

    def close(self) -> None:
        """Release the underlying HTTP connection pool."""
        self.session.close()

    # ---- helpers
    def get_me(self):
        return self.call("getMe")

    def delete_webhook(self):
        return self.call("deleteWebhook", drop_pending_updates=False)

    def get_updates(self, offset, timeout=25):
        return self._get_updates(offset, timeout)

    def _get_updates(self, offset, timeout):
        response = None
        try:
            response = self.session.post(
                f"{self.base}/getUpdates",
                json={"offset": offset, "timeout": timeout, "allowed_updates": ["message", "callback_query", "my_chat_member"]},
                timeout=timeout + 15,
            )
            data = response.json()
            if not isinstance(data, dict) or data.get("ok") is not True:
                d = data if isinstance(data, dict) else {}
                self.poll_error = (d.get("error_code"), d.get("description") or "")
                return None
            self.poll_error = None
            result = data.get("result")
            return result if isinstance(result, list) else None
        except (requests.RequestException, ValueError) as e:
            log.warning("getUpdates failed: %s", e)
            return None
        finally:
            if response is not None:
                response.close()

    @staticmethod
    def _has_style(markup) -> bool:
        return bool(markup) and any("style" in b for row in markup.get("inline_keyboard", []) for b in row)

    @staticmethod
    def _plain_markup(markup):
        return {"inline_keyboard": [[{k: v for k, v in b.items() if k != "style"} for b in row]
                                    for row in markup["inline_keyboard"]]}

    def _with_style_fallback(self, fn, markup):
        """Button colours need a recent Bot API. If a server rejects them, resend plain and stop colouring."""
        if markup and not self.styles_ok:
            markup = self._plain_markup(markup)
        self._tl.last_error = ""
        res = fn(markup)
        if res is None and self._has_style(markup):
            err = (getattr(self._tl, "last_error", "") or "").lower()
            if "style" in err or "button" in err or "reply markup" in err or "reply_markup" in err:
                self.styles_ok = False
                log.warning("server rejected coloured buttons; falling back to plain buttons")
                res = fn(self._plain_markup(markup))
        return res

    def send_message(self, chat_id, text, reply_markup=None, parse_mode=None, reply_to=None):
        reply = {"message_id": reply_to, "allow_sending_without_reply": True} if reply_to else None
        return self._with_style_fallback(
            lambda m: self.call("sendMessage", chat_id=chat_id, text=text, reply_markup=m, parse_mode=parse_mode,
                                reply_parameters=reply, disable_web_page_preview=True), reply_markup)

    def leave_chat(self, chat_id):
        return self.call("leaveChat", timeout=10, chat_id=chat_id)

    def delete_message(self, chat_id, message_id):
        return self.call("deleteMessage", timeout=10, chat_id=chat_id, message_id=message_id)

    def edit_message_text(self, chat_id, message_id, text, reply_markup=None, parse_mode=None):
        return self._with_style_fallback(
            lambda m: self.call("editMessageText", chat_id=chat_id, message_id=message_id, text=text,
                                reply_markup=m, parse_mode=parse_mode, disable_web_page_preview=True), reply_markup)

    def send_rich(self, chat_id, html_text, plain_text, reply_markup=None, reply_to=None):
        """Send as HTML; if Telegram rejects the markup, resend the plain text (never lose the answer)."""
        return (self.send_message(chat_id, html_text, reply_markup, parse_mode="HTML", reply_to=reply_to)
                or self.send_message(chat_id, plain_text, reply_markup, reply_to=reply_to))

    def edit_rich(self, chat_id, message_id, html_text, plain_text, reply_markup=None):
        return (self.edit_message_text(chat_id, message_id, html_text, reply_markup, parse_mode="HTML")
                or self.edit_message_text(chat_id, message_id, plain_text, reply_markup))

    def send_chat_action(self, chat_id, action="typing"):
        return self.call("sendChatAction", timeout=10, chat_id=chat_id, action=action)

    def answer_callback(self, cb_id, text=None):
        return self.call("answerCallbackQuery", timeout=10, callback_query_id=cb_id, text=text)

    def send_document(self, chat_id, filename, data: bytes, caption=None):
        return self.call(
            "sendDocument", timeout=60, files={"document": (filename, data)},
            chat_id=chat_id, caption=caption or "",
        )

    def set_my_commands(self, commands, language_code=None, scope=None):
        params = {"commands": commands}
        if language_code:
            params["language_code"] = language_code
        if scope:
            params["scope"] = scope                  # e.g. {"type": "all_group_chats"} or {"type": "chat", "chat_id": 1}
        return self.call("setMyCommands", **params)

    def get_file_bytes(self, file_id, max_bytes=None):
        """Download a file; returns None on failure or when it exceeds `max_bytes` (checked while streaming)."""
        info = self.call("getFile", file_id=file_id)
        if not info or "file_path" not in info:
            return None
        try:
            with self.session.get(f"{self.file_base}/{info['file_path']}", timeout=60, stream=True) as r:
                if r.status_code != 200:
                    return None
                buf = bytearray()
                for chunk in r.iter_content(65536):
                    buf += chunk
                    if max_bytes is not None and len(buf) > max_bytes:
                        return None
                return bytes(buf)
        except requests.RequestException:
            return None
