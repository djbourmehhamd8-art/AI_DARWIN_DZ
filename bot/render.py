from __future__ import annotations

import threading
import time

from .formatting import render_chunks


class Typing:
    """Keeps the "typing…" indicator alive (Telegram drops it after ~5 s) while the model is thinking."""

    def __init__(self, tg, chat_id, every: float = 4.0):
        self.tg, self.chat_id, self.every = tg, chat_id, every
        self._stop = threading.Event()

    def __enter__(self):
        self.tg.send_chat_action(self.chat_id)
        threading.Thread(target=self._run, daemon=True, name="typing").start()
        return self

    def _run(self):
        while not self._stop.wait(self.every):
            self.tg.send_chat_action(self.chat_id)

    def __exit__(self, *exc):
        self._stop.set()
        return False


class StreamRenderer:
    """Shows a growing answer as formatted Telegram HTML by editing one message, rolling over to new messages
    when the 4096-char limit approaches (code blocks are closed and reopened across the cut).

    `stop_markup` is shown under the live message (⏹ button); `final_markup` replaces it under the last part
    once the answer is complete (retry / continue / shorter ...)."""

    CURSOR = " ▌"

    def __init__(self, tg, chat_id, interval: float = 1.0, stop_markup=None, final_markup=None, reply_to=None):
        self.tg, self.chat_id, self.interval = tg, chat_id, interval
        self.reply_to = reply_to                 # thread the answer under the question (used in groups)
        self.stop_markup, self.final_markup = stop_markup, final_markup
        self.slots: list = []        # one dict per Telegram message: {"id": message_id, "key": last shown state}
        self.last_edit = 0.0
        self._push(0, "…", "…", self.stop_markup, cursor=False)

    # ---- low level
    def _push(self, idx: int, md: str, html_text: str, markup, cursor: bool) -> None:
        if not md.strip():
            return
        tail = self.CURSOR if cursor else ""
        key = (html_text + tail, bool(markup))
        plain = md + tail
        if idx >= len(self.slots):
            res = self.tg.send_rich(self.chat_id, html_text + tail, plain, markup,
                                    reply_to=self.reply_to if idx == 0 else None)
            if res and isinstance(res, dict):
                self.slots.append({"id": res.get("message_id"), "key": key})
        else:
            slot = self.slots[idx]
            if slot["key"] != key and slot["id"] is not None:
                self.tg.edit_rich(self.chat_id, slot["id"], html_text + tail, plain, markup)
                slot["key"] = key
        self.last_edit = time.monotonic()

    def _render(self, full: str, final: bool) -> None:
        parts = render_chunks(full)
        last = len(parts) - 1
        for i, (md, h) in enumerate(parts):
            if i < last:
                self._push(i, md, h, None, cursor=False)
            else:
                self._push(i, md, h, self.final_markup if final else self.stop_markup, cursor=not final)

    # ---- public
    def update(self, full: str) -> None:
        if time.monotonic() - self.last_edit >= self.interval:
            self._render(full, final=False)

    def finish(self, full: str) -> None:
        self._render(full, final=True)

    def fail(self, text: str, markup=None) -> None:
        if self.slots and self.slots[-1]["id"] is not None:
            self.tg.edit_message_text(self.chat_id, self.slots[-1]["id"], text, markup)
        else:
            self.tg.send_message(self.chat_id, text, markup)
