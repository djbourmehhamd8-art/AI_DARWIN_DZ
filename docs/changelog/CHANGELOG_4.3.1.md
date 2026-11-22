# 4.3.1 — Automatic daily limit for approved users

- When an admin approves a user (✅ Approve, ⏳ 7 days, temporary access, card «Allow», or `/allow <id>`), the user is **automatically given
  a limit of 100 messages per day** (`NEW_USER_LIMIT`, default 100, `0` = off). It resets every day.
- A limit an admin already set for that user (including ∞) is never overwritten. Admins are never limited.
- The user is told their daily limit in the approval message; `/quota` shows usage.
- The limit can still be changed per user from the card (📊) or for everyone from the limits screen.
- Tests: `tests/test_v431.py`.
