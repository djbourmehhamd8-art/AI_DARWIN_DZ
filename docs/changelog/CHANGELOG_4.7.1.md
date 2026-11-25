## 4.7.1 — fuzz-tested hardening and back-pressure
- Fuzzed all 42 web tools and 89 offline bot commands with hostile input (huge, nested, binary, RTL, overflow). Three real crashes found and fixed:
  `/json` on deeply nested input (`RecursionError`), `/pass` on passphrases over ~170 characters (`OverflowError` in the crack-time estimate), and the web JWT tool on invalid tokens (`KeyError`). All now give a clean, friendly error.
- **Back-pressure**: the update queue is bounded (8 × workers, minimum 32). Under a flood or slow AI answers the bot stops pulling from Telegram (which keeps the backlog) instead of growing memory without limit; an update that waits over 60 s is shed and logged. Slots are always released, even if a handler crashes.
- Tests: +5 (`tests/test_v471.py`).

