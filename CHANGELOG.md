# CHANGELOG

## 5.4.1 — live streaming answers in the web chat
- **Real streaming**: the answer now appears while the model is writing it (newline-delimited JSON over the same `POST /api/chat` and `/api/regenerate` with `"stream": true`), with the typing caret, instead of waiting for the whole reply. Errors before the first token stay ordinary JSON responses; an error mid-stream is reported inside the stream and nothing half-finished is saved; if the AI client restarts an answer the page gets a `reset`; a closed browser tab never breaks the server-side history. Falls back to the old behaviour when the model client does not stream. `X-Accel-Buffering: no` is sent so nginx-style proxies do not hold the stream back.
- **Bug fix (shipped in 5.4.0)**: the page's own `Permissions-Policy` said `microphone=()`, so the browser always refused voice dictation. It is now `microphone=(self)` (camera, geolocation, payment and USB stay blocked).
- 6 new tests (`tests/test_v540_stream.py`) and a real-browser run showing the partial text before the reply finishes.

## 5.4.0 — tools inside the web chat, 9 new tools, regenerate / export / voice
- **🧰 Tools sheet in the web chat** (button or `Alt+T`): all 49 offline tools of the web panel (hash, JWT, CVSS, IOC, subnet, regex, CSP/cookie/headers checks, SPF/DMARC, secrets scan, …) with search, `Ctrl+Enter` to run, copy, and **"ask the AI about the result"**. Server side: `POST /api/tool` (login + CSRF, 30 runs/min per session, 90/min per IP, output capped).
- **9 new tools** (`bot/moretools.py`, also available in the web panel): Shannon entropy (spot keys/tokens), homograph/IDN lookalike detector, URL breakdown with risk flags (`user@host` trick, obfuscated IPs, open-redirect and double-encoding hints), number-base converter, TOTP generator (RFC 6238 vectors tested; SHA1/256/512, `otpauth://`), port/service lookup, HTTP status reference, HMAC (SHA-256/1/512), hex dump.
- **Chat**: "↻ regenerate" the last answer (`POST /api/regenerate`, slightly higher temperature, the old answer is not fed back), "🔊 read aloud", Markdown **export** (⤓), **voice dictation** where the browser supports it, shortcuts: `/` focus input, `Ctrl+K` new chat, `Esc` close/skip.
- Fixes found by the new tests/UI check: TOTP crashed near the epoch (negative counter); the mobile header rule for `select` leaked into the tools sheet.
- 14 new tests (`tests/test_moretools.py`), end-to-end browser run against a real server with no console errors.

## 5.3.3 — web chat redesign, security audit and hardening
- **New premium web chat UI** (`bot/webchat.py`): animated silver aurora background with a soft sheen, glass header and floating composer, spinning silver orb, shimmering title, smooth message entrance animations.
- **Themes**: follows the system by default; the ◐ button cycles dark → light → system (remembered in the browser).
- **Better answers display**: full Markdown (headings, lists, tables, quotes, links, bold/italic, inline code), code blocks with language label and copy button, "copy reply" action, typewriter reveal (click or Esc to finish it), thinking indicator.
- **Usability**: auto-growing input, character counter near the limit, scroll-to-bottom button, starter suggestions, retry button after an error, mobile layout fixes, reduced-motion support.
- Security model unchanged: CSP nonce, CSRF header, no DOM-string injection (text nodes only), links limited to http(s) with `noopener nofollow`.

## Unreleased — standalone web chat + deep audit fixes
- **The AI chat is now its own website** (`bot/webchat.py`): separate port (`WEB_CHAT_PORT`), cookie, password, session store, CSP and server, so it can be exposed or stopped independently of the admin panel. Removed `/chat` from the panel (routes, sidebar entry, `chat_page`/`chat_send`).
- Access: password (`WEB_CHAT_PASSWORD`, or derived from the bot token with a different label than the panel's; admins get it with `/webchat`) or `WEB_CHAT_PUBLIC=1` for an open site. Limits: per session, per IP, and a site-wide daily cap (`WEB_CHAT_DAILY`).
- New front end: JSON API with a CSRF header, a per-request CSP nonce (the only script is the page's own), no `innerHTML` (model text is rendered with DOM text nodes), code blocks with a copy button, Enter to send.
- `/webchat` in Telegram now opens the new site (public mode: any user; password mode: admin only, password in a self-deleting private message).
- 16 new tests in `tests/test_webchat.py`.

### Deep audit fixes
- **Race in per-chat locks** (`KeyedLocks`): pruning idle locks could drop a lock another thread had just fetched, so two answers for one chat could run at the same time. Locks now live in a `WeakValueDictionary` (an entry vanishes only when nobody references it).
- **SSRF deny-list**: `resolve_public` now explicitly refuses site-local `fec0::/10` (reported as global by the stdlib), 6to4 `2002::/16`, Teredo `2001::/32`, IPv4-mapped, CGNAT and benchmarking ranges, independent of the Python version.
- **Slow-drip downloads**: `fetch_text` had only a per-read timeout, so a server sending one byte at a time held a worker thread for minutes; it now has an overall deadline.
- **RDAP**: a non-JSON or non-object reply returns `{"ok": False}` instead of raising.
- **Maidenhead**: `90N`/`180E` produced the invalid field letter `S`; coordinates are clamped to the `A-R` grid.
- **Space weather**: a Kp index of `0` (quiet sun) was treated as missing and reported as an error.
- **Memory growth**: caches keyed by unknown users/groups (`_denied_seen`, `_denied_shown`, `_welcomed`, `_staff_pinged`, `_group_notice`) are now bounded.
- 8 new tests in `tests/test_v531_audit.py`.

### Audit fixes (web chat + dependencies)
- **Web chat race**: the "answer in progress" flag was checked and set under two different lock acquisitions, so two parallel requests of one session could both reach the AI and overwrite each other's history. The check-and-set is now atomic.
- **Web chat "new chat" during an answer**: a reply that arrived after the history was cleared re-created the old conversation. A per-session generation counter now discards it.
- **Keep-alive desync**: a rejected `Host` (403) on a POST left the request body unread on the persistent connection (web chat and web panel). Those responses now close the connection.
- **Dependency floor**: `requests>=2.32.4` (fixes the netrc credential leak on redirects and the `verify` flag sticking after `verify=False`).
- **Page script**: the typewriter reveal could stall in a background tab (animation frames are paused there); it now finishes instantly when the tab is hidden.
- 3 new tests in `tests/test_webchat.py`.

### Hardening and cleanup pass
- **Connection cap** (`LimitedHTTPServer`, web chat and web panel): at most 64 simultaneous connections; extra ones get an immediate `503 Retry-After`, so idle sockets can no longer exhaust the process with unlimited threads.
- **Cross-site POST refused**: requests the browser marks `Sec-Fetch-Site: cross-site/same-site` are rejected (defence in depth next to SameSite cookies and the CSRF header; works behind any reverse proxy).
- **Regex sandbox**: the child interpreter now also has a memory ceiling (768 MB address space) and a 5 s CPU limit.
- **Cleanup**: removed dead code (`broadcast_ids`, `extra_commands`, `hex_decode`, `url_decode`, an unused import) and renamed unused locals; no behaviour change.

### Second audit pass
- **Crash on forged placeholder**: Telegram formatting uses `\x00<n>\x00` internally to protect code spans. Text that already contained such a sequence (model output, web pages, uploaded files) made `to_html` raise `IndexError` (or swap in another code span). NUL characters are now stripped before the placeholders are created.
- **`/webchat` lost the message on local setups**: without `WEB_CHAT_URL` the button pointed at `http://127.0.0.1:<port>`, which Telegram rejects, so the whole message (including the password) never arrived. A local address is now shown in the text; a public address keeps the button.
- 4 new tests in `tests/test_v532_audit.py`.

## 5.3.0 — stronger protection and cleanup
- **Host allow-list on exposed binds**: when `WEB_PANEL_HOSTS` or `WEB_PANEL_URL` is set, unknown `Host` headers get `403` even when the panel listens on `0.0.0.0` (Docker/hosting), which closes the DNS-rebinding gap there. Without an allow-list nothing changes. `/healthz` answers any Host so platform probes keep working.
- **More response headers**: `Cross-Origin-Opener-Policy`, `Permissions-Policy`, and `Strict-Transport-Security` when the panel is served over HTTPS.
- **Deployment sandbox**: `docker-compose.yml` now runs read-only with `cap_drop: ALL`, `no-new-privileges`, tmpfs `/tmp`, and pid/memory limits; `deploy/darwin.service` adds an empty capability set, private devices, address-family and syscall filters, and a task limit.
- **Cleanup**: removed the dead `SecurityCommands.cmd_cve` and `WorkspaceMixin.cmd_save` (always shadowed by newer versions) and the shadowing allow-list in `test_v490` is now empty, so any future clash fails the tests. One `USER_AGENT` (`bot.USER_AGENT`, built from the version) replaces five hard-coded, stale strings.
- 8 new tests in `tests/test_v530.py`.

## 5.2.1 — hardening pass (audit fixes)
- **Web panel**: requests carrying `Transfer-Encoding` are refused with `501` and the connection is closed. The panel reads bodies by `Content-Length` only, so a chunked body used to stay unread on the keep-alive connection; behind a reverse proxy that honours `Transfer-Encoding` that length mismatch is the classic request-smuggling precondition.
- **Setup page** (`bot/setupmode.py`): idle/slow clients are dropped after 15 s (no more threads parked forever on an unauthenticated port), and `HEAD` is answered without a body.
- **WEB_PANEL_TOKEN shorter than 12 characters** was silently replaced by the derived password (the `validate()` check could never fire), so the owner's own password just "didn't work". A warning now says it is ignored and how to get the real one (`/web`).
- **`.env.example`** documents every variable the code reads (`DB_PATH`, `LOG_FILE`, `MAX_CONTEXT_CHARS`, `MAX_INPUT_CHARS`, `PRICE_IN/OUT`, `TELEGRAM_API_URL`, `WEB_PANEL_HOST(S)`, `PORT`) and states that `PUBLIC` defaults to **true**. A test keeps code and example in sync.
- 6 new tests in `tests/test_v521.py`.

## 5.2.0 — logs page, DB indexes, Docker, lint
- **📜 السجلات** (`/logs`): آخر التحذيرات والأخطاء في لوحة الويب (حلقة ذاكرة `bot/ringlog.py`، بحث وتصفية بالمستوى) مع إخفاء المفاتيح والتوكنات وتهريب HTML؛ لا شيء يُكتب على القرص.
- **أداء**: فهارس جديدة لجداول `audit` و`users` و`daily` تُنشأ تلقائياً عند التشغيل (آمنة على القواعد القديمة) لتسريع اللوحة على القواعد الكبيرة.
- **Docker**: `Dockerfile` (مستخدم غير مميّز، فحص صحة عبر `/healthz`) و`docker-compose.yml` (المنفذ مربوط بـ127.0.0.1) و`.dockerignore`.
- **جودة**: `make lint` (ruff لأخطاء حقيقية فقط) وخطوة lint في CI.
- يتضمن كل ما في 5.1.x أدناه.

## 5.1.2 — web admin: groups, settings, broadcast, roles
- **🏘 المجموعات** (`/groups`): كل المجموعات في جدول (الحالة، الاستخدام اليومي/الحد، آخر نشاط) مع تفعيل/إيقاف وحد يومي لكل مجموعة ومغادرة بتأكيد.
- **⚙️ الإعدادات** (`/settings`): وضع الصيانة، الحدود اليومية الافتراضية للمستخدم والمجموعة، **بث رسالة** لكل المستخدمين المفعّلين (في الخلفية، مع تأكيد وتهريب HTML، والناتج في السجل `web_broadcast_done`)، فحص سلامة قاعدة البيانات، وتنزيل نسخة احتياطية.
- **صفحة المستخدم**: ترقية/سحب صفة مشرف ومسح محادثات المستخدم (بتأكيد). المديرون محميون.
- **واجهة جديدة** (`bot/webui.py`): قائمة جانبية مجمّعة بشارات (طلبات معلّقة / بلاغات مفتوحة)، شريط علوي ببحث سريع عن مستخدم، قائمة متجاوبة للجوال بلا JavaScript، تنبيهات ملوّنة حسب النتيجة، جداول بتظليل وتمرير، ووضع طباعة.
- **إجراءات جماعية** في المستخدمين: تحديد عدة مستخدمين أو «كل نتائج الفلتر الحالي» (حتى 500) ثم موافقة/رفض/حظر/فك حظر/سحب، بتأكيد، مع تخطي المحميين وتسجيل `web_bulk_*`.
- **دقة**: مقارنة رسائل اليوم بالأمس ومتوسط 7 أيام في النظرة العامة، وترقيم بأزرار «الأولى/الأخيرة».
- نفس نموذج الأمان: جلسة + CSRF لكل POST + بلا JavaScript + تهريب كامل + تسجيل في سجل التدقيق. وحدة جديدة `bot/webctl.py` و14 اختباراً في `tests/test_webctl.py`.

## 5.0.1 — release-archive fix and cleanup
- **Bug**: `scripts/build_release.py` wrote every file as `0644`, so the `.sh` scripts (`start.sh`, `stop.sh`, `install_termux.sh`, `deploy/*.sh`) lost their executable bit in the ZIP and `tests.test_v40.DeployKit` failed on an unpacked release. Scripts (`.sh` or a `#!` first line) are now stored as `0755`. Regression test added.
- **Bug**: rebuilding from a tree that already held `RELEASE-MANIFEST.json` put that file in the ZIP twice (duplicate entry, `unzip` prompts to overwrite). The manifest is now excluded from the file scan and regenerated once. Regression test added.
- **Docs**: merged the duplicated `# CHANGELOG` / `# Changelog` headings into one file and removed the stale "(latest)" label from 4.5.2.
- No bot, web-panel or storage code changed.

## 5.0.0 — platform foundation and controlled agent runtime
- **Major release baseline**: preserve the existing Telegram, web panel, storage, security tools and provider integrations; no destructive rewrite.
- **Agent runtime foundation** (`bot/agent_runtime.py`): explicit tool allowlist, bounded plans and arguments, sequential execution, cancellation checks, task time budget, output-size cap, and human approval gate for sensitive tools. No model-generated shell/code execution is provided.
- **Release engineering** (`scripts/build_release.py`): reproducible source ZIP with SHA-256 manifest; excludes `.env`, runtime databases, logs, caches, virtual environments and all `data/` contents except `.gitkeep`.
- **Tests and CI**: agent policy regression tests and a release-archive hygiene check; corrected the quick fuzzer network-command skip list so `/dist` (geocoding) is not mistaken for an offline pure function.
- **Version**: 5.0.0. This is a foundation release; the new agent runtime is a reusable core component and is not yet wired into a user-facing Telegram command.


## 4.9.1 — hardening pass
- **Security (DoS)**: the `/regex` tester (also on the unauthenticated `/t` web page) could freeze the whole bot with patterns such as `(a?){28}a{28}` or `a*a*a*a*a*a*b`, because the nested-quantifier filter is bypassable and `re` never releases the GIL. Matching now runs in a throw-away interpreter (`python -I`) with a 2 s hard timeout and at most 4 concurrent children.
- **Bug**: `bot/security/ports.py` used a backslash inside an f-string expression: a SyntaxError on Python 3.9-3.11 (the declared minimum is 3.9), so the whole module failed to import there.
- **Bug**: `calc("(-8)**0.5")` returned a complex number; now rejected. `netintel.valid_domain("http://[abc")` raised ValueError instead of returning None.
- **Robustness**: JSON nesting is bounded explicitly (200 levels) instead of relying on the interpreter's recursion limit (Python 3.13 no longer raises, which broke `test_deeply_nested_json_is_a_clean_error`).
- Lint: all ruff findings fixed (unused variables, empty f-strings). Tests: +6 (`tests/test_v491.py`).

## 4.9.0 — problem reports and admin web panel v2
- **Problem reports**: `/problem` (aliases `/bug`, `/issue`, `/feedback`) and a 🐞 main-menu button. Five kinds (bug, wrong tool result, idea, abuse, other); only the bot version, language and the user's last tool are attached, never chats. Private chat only, 5 per day and 10 open per user, duplicates ignored. Admins get an alert with View / Close / Reply buttons; `/reports [open|closed|all|id]`, `/replyreport <id> <text>`; replies and closures reach the user automatically. `/myreports` shows status. (`/report` is unchanged: it is still the AI incident report from the case history.)
- **Admin web panel v2**: `/overview` (KPI cards, 14-day message and signup charts in pure CSS, pending requests with one-click approve/reject, top users today, open reports, system health, latest events); `/reports` inbox (search, kind and status filters, reply and close from the web, confirm-to-delete, CSV, open-count badge in the nav); `/user?id=` (profile, 14-day activity, related reports and events, all moderation actions, direct message to the user); `/audit` with search, action filter, pagination and CSV. User ids in the users table link to the detail page; actions can return to the page they came from (open-redirect safe).
- Storage: `reports` table, audit search, overview queries; daily usage kept 35 days (was 7) so the charts have data.
- Tests: +36 (`tests/test_v490.py`), including a guard that fails when one mixin silently hides another's method, and hostile query-string tests for every new page. Two old tests were updated for deliberate changes (35-day retention, linked user ids).

## 4.8.0 — tools hub, 10 new tools, project tooling
- **Tools hub** (`/hub`, `/tools`, main-menu button): 5 categories, `/tools <word>` search (names, labels, keywords), per-user ⭐ recent tools. Main menu reduced from 8 busy rows to 6.
- **New tools** (offline, also on the web panel): `/spf`, `/dmarc` (email-auth audits), `/secrets` (leak scanner: AWS/GitHub/GitLab/Slack/Google/Stripe/Telegram/OpenAI keys, private keys, JWTs, creds in URLs, password assignments; always masked; deletes your message), `/sri`, `/chmod`, `/cidrmatch`, `/ipconv`, `/useragent`, `/diff`, `/date`.
- **Stricter grading**: one high-severity finding caps a grade at C, two at D, a fatal one (SPF `+all`) at F.
- **Fixed**: `/fspl` regex backtracking (a 100 KB input ran for over a minute); local tools now cap input at 60 000 chars (typed or uploaded).
- **Project quality**: `scripts/fuzz.py` (CI smoke + full run, also flags slow calls), `Makefile` (`make check`), `pyproject.toml`, `docs/ARCHITECTURE.md` (add-a-tool in 5 steps), `CONTRIBUTING.md`, registry guard test that fails if a tool is half-registered. CI also runs the fuzz smoke and compiles `scripts/`.
- Tests: +34 (`tests/test_v480.py`).

## 4.7.1 — fuzz-tested hardening and back-pressure
- Fuzzed all 42 web tools and 89 offline bot commands with hostile input (huge, nested, binary, RTL, overflow). Three real crashes found and fixed:
  `/json` on deeply nested input (`RecursionError`), `/pass` on passphrases over ~170 characters (`OverflowError` in the crack-time estimate), and the web JWT tool on invalid tokens (`KeyError`). All now give a clean, friendly error.
- **Back-pressure**: the update queue is bounded (8 × workers, minimum 32). Under a flood or slow AI answers the bot stops pulling from Telegram (which keeps the backlog) instead of growing memory without limit; an update that waits over 60 s is shed and logged. Slots are always released, even if a handler crashes.
- Tests: +5 (`tests/test_v471.py`).

## 4.7.0 — web-hardening auditors, network & scheduling helpers
- **`/csp`** audits a Content-Security-Policy (unsafe-inline/eval, wildcards, JSONP-prone hosts, missing object-src/base-uri/frame-ancestors/form-action) with a 0–100 score and A–F grade.
- **`/cookie`** audits a `Set-Cookie` line (Secure, HttpOnly, SameSite, `__Host-`/`__Secure-` prefix rules, lifetime, Domain scope). The cookie value is never echoed or stored.
- **`/secheaders`** grades a pasted HTTP response header block: HSTS, CSP, nosniff, framing, Referrer/Permissions/COOP/CORP, CORS misconfigurations, version leaks, weak cookies.
- **`/subnet`** CIDR calculator (IPv4/IPv6, netmask form, wildcard, range, usable hosts) with splitting: `/subnet 10.0.0.0/24 /26`.
- **`/cron`** explains a 5-field cron expression or `@macro` and lists the next runs (UTC), with standard day-of-month/day-of-week OR semantics.
- All five are offline, rate-limited, available as menu buttons (🧮 Extra tools), accept the replied-to message, and run on the public `/t` web page and the panel tools page.
- Tests: +30 (`tests/test_v470.py`).

## 4.6.0 — hosting-ready, public web tools, no more crash loops
- **3 essential variables only** (`TELEGRAM_TOKEN`, `API_KEY`, `ADMIN_IDS`). `TELEGRAM_BOT_TOKEN` / `BOT_TOKEN` / `TOKEN` are accepted and the token is cleaned (spaces, quotes, `bot` prefix).
- **Web interface starts automatically** on the host's `PORT` (binds 0.0.0.0). `WEB_PANEL_TOKEN` is no longer required: a strong password is derived from the bot token; admins get it with `/web` (self-deleting message). A too-short explicit token no longer stops the bot.
- **New public page `/t`** (no login): offline calculator/converters plus Hash, password strength, JWT inspect, CVSS, multi-layer decode, timestamps and IOC extraction. Rate-limited per IP, nothing stored, output escaped. Public home page `/` with the bot link.
- **No crash loops**: a rejected token (401) or unreachable Telegram no longer exits the process; the bot retries with back-off and the web panel stays up. `/system` shows the exact reason and fix. Missing essentials start a "setup mode" page instead of exiting.
- **Security**: provider error text is scrubbed of URLs (the 402 pay link carried the account key and was written to logs). Expected per-user Telegram errors (blocked / not found) are no longer logged as warnings. A stale webhook that causes 409 is removed automatically.
- `.env.example` reduced to the essentials; `deploy/FADEHOST.md` rewritten for FadeHost with a troubleshooting table.
- Tests: +14 (`tests/test_v460.py`); the 7 new web tools are covered in `test_v450`.

## Older versions (before 4.6)

Full notes per version are in `docs/changelog/`.
- **[4.5.2](docs/changelog/CHANGELOG_4.5.2.md)** — Bug-fix pass: multi-line command arguments, safe numeric parsing, .env parsing, damaged zip members
- **[4.5.1](docs/changelog/CHANGELOG_4.5.1.md)** — Audit pass: 409 notice to admins, cheaper writes, faster tests
- **[4.5.0](docs/changelog/CHANGELOG_4.5.0.md)** — AI chat in the web panel, 13 extra tools with buttons, audit & system pages
- **[4.4.4](docs/changelog/CHANGELOG_4.4.4.md)** — Permanent access for every user (no temporary grants), history kept forever
- **[4.4.3](docs/changelog/CHANGELOG_4.4.3.md)** — Security & correctness audit fixes
- **[4.4.2](docs/changelog/CHANGELOG_4.4.2.md)** — Open access, 50 messages/day for every new user, web panel button for admins
- **[4.4.0](docs/changelog/CHANGELOG_4.4.0.md)** — Web panel for user management
- **[4.3.1](docs/changelog/CHANGELOG_4.3.1.md)** — Automatic 100 messages/day for approved users
- **[4.3.0](docs/changelog/CHANGELOG_4.3.0.md)** — Live world: aircraft radar, radio, space, web portals
- **[4.2.0](docs/changelog/CHANGELOG_4.2.0.md)** — Conversation manners, advanced tools, verified answers
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

## 4.5.2 — Bug-fix pass
See `docs/changelog/CHANGELOG_4.5.2.md`.

## 4.5.1 — Audit pass
See `docs/changelog/CHANGELOG_4.5.1.md`.

## 4.5.0 — AI chat on the web, extra tools
See `docs/changelog/CHANGELOG_4.5.0.md`.

## 4.4.4 — Permanent access
See `docs/changelog/CHANGELOG_4.4.4.md`.

## 4.4.3 — Security & correctness audit fixes
See `docs/changelog/CHANGELOG_4.4.3.md`.

## 4.4.0 — Web panel for user management
See `docs/changelog/CHANGELOG_4.4.0.md`.

## 4.3.1 — Automatic daily limit (100 msgs) for approved users
See `docs/changelog/CHANGELOG_4.3.1.md`.

## 4.3.0 — Live world: aircraft radar, radio, space, web portals

## ✈️ Aircraft radar (public ADS-B)
- `/radar <city|lat,lon> [km]` — aircraft around a place: a **text radar scope** (north up, rings, numbered contacts), a list with
  callsign, type, flight level, speed, heading, distance and compass direction, plus a button that opens the live map **inside Telegram**.
- `/flight <callsign>`, `/plane <registration|hex>`, and `/squawk` for aircraft squawking **7700 / 7600 / 7500** (general emergency,
  radio failure, hijack — with a reminder that a code can be a mistake or a drill).
- Two independent feeds (adsb.lol → airplanes.live), 8-second cache and a 1 req/s gap per host; every input is validated before it enters a URL.
  The bot says plainly that the data is crowd-sourced, can be delayed or incomplete, and is **never for navigation or safety**.

## 🌦 Weather, space and Earth
- `/metar <ICAO>` (flight category 🟢🔵🔴🟣, wind, visibility, QNH + TAF), `/weather <city>` (now + 3 days, Arabic/English conditions),
  `/iss [city]` (position, altitude, speed, distance to you, map button), `/space` (Kp, solar flux, NOAA R/S/G scales and a rough **HF propagation outlook**),
  `/quakes [min magnitude]` (USGS, tsunami flag).

## 📻 Radio communications
- `/radio <name|country code>` internet radio (e.g. `/radio DZ`) with stream links.
- Offline calculators: `/freq` (what lives on a frequency: bands, aviation/marine distress, ADS-B 1090, ISS 145.800, APRS, weather satellites, GNSS, ISM/LoRa, Wi-Fi…),
  `/wave` (wavelength, dipole and quarter-wave lengths), `/morse` (both ways), `/phonetic` (NATO), `/qcode` (31 codes incl. QNH/QFE/QNE),
  `/grid` (Maidenhead ⇄ coordinates), `/power` (dBm ⇄ W), `/fspl` (free-space path loss), `/horizon` (radio horizon), `/dist` (distance, bearing, locators).
  Allocations are ITU Region 1 at a general level; the bot reminds users to check their national regulator before transmitting.
- Tools guide: new **Radio, SDR & reception** category (RTL-SDR, SDR++, GNU Radio, readsb/tar1090, WSJT-X, SatDump…).

## 🧬 More passive security intelligence
- `/subdomains` (certificate-transparency logs, nothing sent to the target), `/asn` (network, holder, abuse contact via RIPEstat),
  `/rdns`, `/mac` (only the 3-byte OUI leaves the bot; flags randomised addresses), `/exposure` (what Shodan InternetDB already knows about *your* IP/domain:
  ports, CPEs, CVEs — and the bot nudges you to verify each CVE). All refuse private/internal targets without making a request.

## 🧭 Web portals inside the bot
- `/portals` (and 🌍 World → portals): **39 live sites in 6 categories** — aviation radar, ships, space, radio receivers (WebSDR, KiwiSDR, Radio Garden),
  weather/Earth, and live cyber-threat maps. In private chats the buttons are **Mini-App buttons that open inside Telegram**; groups get ordinary links.
  If a server rejects Mini-App buttons the bot falls back to plain links automatically (`WEBAPP_BUTTONS=false` forces links).
- New **🌍 Live world** entry in the main menu with every tool one tap away, plus a **radio toolbox** screen.

## 🔐 Hardening found while testing
- The stdlib treats **multicast** addresses as "global": `224.0.0.1` passed our public-address check. Both the page-fetch guard and the new
  network tools now refuse multicast.

## Tests
`python -m unittest discover -s tests -t .` — new `tests/test_v43.py` (51 tests): maths against known values (FSPL, Maidenhead IO91wm, haversine), feed fallbacks, input validation, private-target refusal, Mini-App fallback.
