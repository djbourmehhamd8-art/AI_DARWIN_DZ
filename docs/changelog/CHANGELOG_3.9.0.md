# DARWIN DZ 3.9.0 — Private-bot access, groups, multi-level admin

## 🔒 Clear access screen
People without permission now see **why**: a private bot for cybersecurity content, their ID, and how to get access —
**🔑 Request access** (one tap, goes to the admins), **📩 Message @DARWIN0DZ**, and an AR/EN toggle. Pending, declined
and restricted states are shown. One request per user per day. Owner handle via `CONTACT`.

## 👑 Admin control (two levels)
- **Admin**: everything. **Moderator** (`🛡 Make mod` on a user card, `/panel`): users, access requests, approve/reject,
  allow/disallow, temporary access, ban/unban. Moderators cannot touch admins, other moderators or themselves, and
  every admin-only action is refused server-side (not just hidden).
- **Access requests** arrive with ✅ Approve · ⏳ 7 days · ❌ Reject · 🚫 Ban; the user is notified automatically.
- **Temporary access** 1/7/30 days (expires by itself, audited).
- **Per-user daily limit** (default / 10 / 50 / 200 / ∞), **✉️ direct message** to a user (`/dm id text`), **🏆 top users**,
  **📤 users CSV** (formula-injection safe), **🔔 requests** list, **🛡 staff** list, **👥 groups** manager, maintenance mode.

## 👥 Groups
- Write **`DZ <question>`** (or `دي زد …`, a @mention, or reply to the bot) and it answers in a thread, concise and
  with no big keyboard. Example: `DZ كم عدد دول العالم؟`. Bare `DZ` shows usage.
- Safety: a group must be **activated by an admin** (🆗 button when the bot is added, `/allowgroup`, or `GROUP_OPEN=true`).
  If an admin adds the bot it is activated automatically. Members without personal access can ask questions
  (daily cap `GROUP_MEMBER_LIMIT`) and use only /help /id /ask /search.
- Welcome message when the bot is added; staff are pinged (throttled) when an unactivated group tries to use it.
- ⚠️ **Telegram Privacy Mode**: to see plain "DZ …" messages the bot must be a group **admin** or have Privacy Mode
  disabled in @BotFather (`/setprivacy` → Disable). The bot warns about this in the log, the welcome message and the
  System screen.

## 🧰 New tools
`/hex` (text ⇄ hex ⇄ dec/bin/oct ⇄ base64), `/caesar` (shift or all 25 + ROT13), `/entropy` (Shannon entropy,
alphabet mix, hex/base64 shape, random-vs-text verdict) — in the Tools menu too.

## 🐞 Fixes / hardening
- Moderators always count as having access; `STAFF` checks run on the server for every admin button.
- Coloured-button URL buttons supported; `my_chat_member` updates handled; reply threading for group answers.

## Tests
`python -m unittest discover -s tests -t .` — new `tests/test_v39.py` (37 tests).
