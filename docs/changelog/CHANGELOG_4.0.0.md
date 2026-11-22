# DARWIN DZ 4.0.0 — Audited, deployment-ready release (FadeHost / any VPS)

## 🐞 Defects found by the second audit pass (all fixed, all covered by tests)
- **A stale "Approve" button could un-ban a banned user** (a request message sent before the ban). Approve / 7-days /
  temporary access now refuse banned users ("unban first").
- **A cancelled ✉️ message could leak its target into a later `/dm`** and send text to the wrong person. The button
  flow and the `/dm <id> <text>` command are now separate paths; a stale target is never reused.
- **Reply flooding:** every message from a non-authorised person re-sent the whole access screen. Now at most one per 20 s.
- **Access-request flood:** more than 15 requests/hour are recorded but no longer ping the staff again.
- `python main.py --check` could print the bot token through a library error line; the token and keys are now redacted.

## 🚀 Deployment kit (`deploy/`)
- `install_vps.sh` — one command on Debian/Ubuntu: system packages, dedicated `darwin` user, virtualenv, systemd
  service, daily backup cron. Re-run it to **update** (never touches `.env` or `data/`, restarts automatically).
- `darwin.service` — auto-restart, graceful stop, sandbox (no new privileges, read-only system, writes only to `data/`).
- `backup.sh` — consistent SQLite backup while the bot runs, private permissions, 7-day retention.
- `run_tmux.sh` — fallback for hosts without systemd. `FADEHOST.md` — full Arabic guide + troubleshooting.
- `python main.py --check` — preflight: Python/SQLite versions, config, `.env` permissions, data folder, database
  integrity, Telegram token, network reachability (Telegram, AI API, web search), Privacy Mode warning.
  Sends no AI request and prints no secrets.
- Startup hardening: `umask 077`, data folder 700, database and log files 600.

## Tests
`python -m unittest discover -s tests -t .` — new `tests/test_v40.py` (10 tests) and 5 regression tests in `tests/test_v39.py`.
