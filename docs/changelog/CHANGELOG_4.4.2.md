# 4.4.2 — Open access and automatic daily limit

- **No access requests:** `PUBLIC` now defaults to `true` when it is not set in `.env`. Anyone who is not banned can use the bot at once; the
  "🔑 Request access" button is hidden (it returns with `PUBLIC=false`). Banned users still see the restriction screen.
- **50 messages per day for every NEW user:** the limit (`NEW_USER_LIMIT`, default 50, `0` = off) is applied the first time a user is seen,
  not only on approval. It never overrides a limit an admin already chose, and admins are never limited. The counter resets daily at 00:00 UTC.
- **🌐 Users web panel button:** always shown in the admin panel (admins only). With `WEB_PANEL_URL` it opens the panel; without it, it shows how to
  open or enable the panel instead of being missing.
- Existing users are not changed. Tests updated and extended (`NewUserDefault` in `tests/test_v431.py`).

## Review fixes
- `Config.public` now defaults to `True` in the dataclass as well as in `.env` loading (they used to disagree); tests that need a private bot set `public=False` explicitly.
- Automatic 50/day grants to brand-new users are no longer written to the audit log (a public bot would push real admin actions out of its 2000-row cap).
- README / `.env.example` no longer describe the bot as private by default; the security notes now mention the API-cost risk of an open bot.
- The empty `data/bot.db` was removed from the package (runtime data is git-ignored).
