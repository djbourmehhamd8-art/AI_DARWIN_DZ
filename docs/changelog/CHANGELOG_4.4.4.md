# 4.4.4 — Permanent access

- Removed temporary access completely: the "7 days" and 1/7/30-day buttons (Telegram panel, request notification, web panel) are gone.
- Every approval is now permanent. `allowed()` no longer expires anyone, and on startup any old `expires_at` value is reset to 0, so users who had a temporary grant stay forever.
- History is kept forever by default (`RETENTION_DAYS=0`).
- CSV export no longer has an "expires" column.
- Tests updated for permanent access.
