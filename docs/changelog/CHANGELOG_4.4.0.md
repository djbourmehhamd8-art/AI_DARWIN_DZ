# 4.4.0 — Web panel for user management

- New optional **web panel** (`bot/webpanel.py`, no new dependencies): all users in one table with search (id / @username / name),
  filters (pending, allowed, banned, rejected, staff), sorting, pagination, today's usage vs limit, and CSV export (formula-injection safe).
- One-click actions per user: approve (gets the automatic daily limit), approve 7 days, reject, ban / unban, revoke, set daily limit.
  Users are notified in Telegram; admins and moderators cannot be modified; every action goes to the audit log as `web_*`.
- Security: off by default; loopback-only by default; token login, HttpOnly + SameSite=Strict session cookie, CSRF token on every action,
  login rate limit, Host-header check (DNS-rebinding), strict CSP, no JavaScript, all output escaped; the panel token is redacted from logs.
- Config: `WEB_PANEL_PORT`, `WEB_PANEL_TOKEN`, `WEB_PANEL_HOST`, `WEB_PANEL_HOSTS`. If the port is busy the bot still starts.
- Includes 4.3.1 (automatic `NEW_USER_LIMIT=100` on approval). Tests: `tests/test_v440.py`.
- `WEB_PANEL_URL`: shows a **🌐 Users web panel** button (admins only) in the Telegram admin panel that opens the panel in the browser; the URL's host is accepted automatically. Tests: `AdminButton` in `tests/test_v440.py`.
