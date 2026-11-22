# 4.5.1 — Audit pass

- Telegram 409 (a second copy polling with the same token): admins now get a Telegram message explaining it (at most every 6 hours) and an audit entry.
- The "typing…" indicator no longer delays the answer: its first ping runs in the background.
- Daily-quota counter: one commit per message and old rows pruned hourly instead of on every message; audit log trimmed every 50th entry.
- Web panel server stops faster; the test suite no longer waits on server shutdown polling (265 s -> 58 s).
- Verified: no undefined names or unused imports; 420+ tests pass. Measured bot-side cost is ~1-2 ms per message: time is spent in Telegram and the AI provider, not in this code.
