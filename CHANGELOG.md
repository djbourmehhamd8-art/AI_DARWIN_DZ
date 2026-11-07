# Changelog

Newest first. Full notes per version are in `docs/changelog/`.

## Versions
- **[4.1.0](docs/changelog/CHANGELOG_4.1.0.md)** — Strict groups, daily limits, resilient web search, GitHub-ready
- **[4.0.0](docs/changelog/CHANGELOG_4.0.0.md)** — Audited, deployment-ready release (FadeHost / any VPS)
- **[3.9.0](docs/changelog/CHANGELOG_3.9.0.md)** — Private-bot access, groups, multi-level admin
- **[3.8.0](docs/changelog/CHANGELOG_3.8.0.md)** — Full audit release
- **[3.7.0](docs/changelog/CHANGELOG_3.7.0.md)** — Web search, file export, expert mode
- **[3.6.0](docs/changelog/CHANGELOG_3.6.0.md)** — Admin panel, colours, security fix
- **[3.5.0](docs/changelog/CHANGELOG_3.5.0.md)** — Answer quality release
- **[3.4.0](docs/changelog/CHANGELOG_3.4.0.md)** — Organisation release
- **[3.3.0](docs/changelog/CHANGELOG_3.3.0.md)** — DARWIN DZ 3.3.0
- **[3.2.3](docs/changelog/CHANGELOG_3.2.3.md)** — Expert response tuning and regression fix
- **[3.2.1](docs/changelog/CHANGELOG_3.2.1.md)** — Reliability and configuration hardening

---

## 4.1.0 (latest) — Strict groups, daily limits, resilient web search, GitHub-ready

## 🔒 Fix: the bot answered in groups that were never authorised
Personal access used to open **any** group: an approved user, a moderator or an admin was answered everywhere, and
old buttons kept working. Now **only an activated group is served** — nobody in an inactive group gets an answer, commands
and buttons included (the group gets one throttled notice and the admins a ✅ Activate button). `PUBLIC=true` does not
open groups either. Activation: the button, `/allowgroup`, the panel, or `GROUP_OPEN=true` (explicitly open).

## 📊 Daily message limits (admin panel → 📊)
- **Per user** (user card → 📊), **per group** (group card → 📊 Group daily limit, counts every member's messages together)
  and **defaults for all users / all groups** (changed live, persisted; "default" falls back to `.env`).
- Presets 10 · 25 · 50 · 100 · 200 · 500 · ∞ · default; `0` = unlimited. A personal override beats the default;
  admins are exempt. The user card and group card show today's usage; the group gets a clear message when its cap is hit.
- New env: `GROUP_DAILY_LIMIT` (default per group). Moderators cannot change limits.

## 🔎 Fix: "Web results are unavailable right now"
DuckDuckGo often blocks datacenter IPs (HTTP 202/403 or an anti-bot page with status 200), which silently killed search.
Now a **provider chain**: Brave API (`BRAVE_API_KEY`, free) → your SearXNG (`SEARXNG_URL`) → DuckDuckGo HTML →
DuckDuckGo Lite → **Wikipedia** (always reachable; Arabic queries use ar.wikipedia). Anti-bot pages are detected, a blocked
provider is skipped for 5 minutes, identical queries are cached for 10 minutes, and the Sources line names the provider.
- Admin: `/websearch [query]` or the 🔎 button shows every provider's result and the reason it failed; the System screen
  shows the last search; `python main.py --check` runs a real search probe and advises `BRAVE_API_KEY`.

## 🧰 More
- Daily admin report (📈 button, or automatically with `DIGEST_HOUR=9`), maintenance mode now **persists across restarts**.
- Clear startup errors: revoked token (401) stops with an explanation; **409 Conflict** (a second copy of the bot, e.g. Termux
  still running with the same token) is logged with the cause every 30 s.
- Command menus: groups see `/help /search /id`; admins also see `/panel`.
- GitHub: `CHANGELOG.md` + `docs/changelog/`, `SECURITY.md`, CI (tests on Python 3.9–3.12, shell syntax, secret scan),
  `.gitattributes`, stricter `.gitignore`, `deploy/update.sh` (pull + backup + restart + preflight), `docs/GITHUB_UPLOAD.md`.

## Tests
`python -m unittest discover -s tests -t .` — new `tests/test_v41.py` (25 tests).
