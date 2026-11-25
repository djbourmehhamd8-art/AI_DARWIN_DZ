## 4.8.0 — tools hub, 10 new tools, project tooling
- **Tools hub** (`/hub`, `/tools`, main-menu button): 5 categories, `/tools <word>` search (names, labels, keywords), per-user ⭐ recent tools. Main menu reduced from 8 busy rows to 6.
- **New tools** (offline, also on the web panel): `/spf`, `/dmarc` (email-auth audits), `/secrets` (leak scanner: AWS/GitHub/GitLab/Slack/Google/Stripe/Telegram/OpenAI keys, private keys, JWTs, creds in URLs, password assignments; always masked; deletes your message), `/sri`, `/chmod`, `/cidrmatch`, `/ipconv`, `/useragent`, `/diff`, `/date`.
- **Stricter grading**: one high-severity finding caps a grade at C, two at D, a fatal one (SPF `+all`) at F.
- **Fixed**: `/fspl` regex backtracking (a 100 KB input ran for over a minute); local tools now cap input at 60 000 chars (typed or uploaded).
- **Project quality**: `scripts/fuzz.py` (CI smoke + full run, also flags slow calls), `Makefile` (`make check`), `pyproject.toml`, `docs/ARCHITECTURE.md` (add-a-tool in 5 steps), `CONTRIBUTING.md`, registry guard test that fails if a tool is half-registered. CI also runs the fuzz smoke and compiles `scripts/`.
- Tests: +34 (`tests/test_v480.py`).

