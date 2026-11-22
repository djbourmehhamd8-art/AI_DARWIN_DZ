# DARWIN DZ 3.7.0 — Web search, file export, expert mode

## 🔎 Web-grounded answers
- Answers can use live web results (DuckDuckGo, no API key). Per-user mode in Settings → Web search or `/web`:
  **Off / Auto / Always**. Auto searches only when the question needs fresh data (news, prices, versions, CVEs…).
- `/search <question>` and the 🔎 buttons force a search; the 🔎 button under an answer redoes it with the web.
- Results (and excerpts of the top pages) go to the model as **untrusted data**; answers cite `[1] [2]` and a
  collapsible **Sources** quote follows with clickable links. If the web is unreachable the answer still arrives.
- Privacy/safety: secrets are masked before the query leaves the bot; page fetching blocks private/loopback/
  link-local addresses, credentials in URLs, odd ports, unsafe redirects; size and time are capped.
- Config: `WEB_SEARCH=false` disables it globally; `WEB_DEFAULT=off|auto|on`, `WEB_RESULTS`, `WEB_PAGES`.

## 📁 File export (for programmers)
- 📁 **Files** button under every answer, in the main menu and in Settings, or `/files`:
  TXT · MD · HTML (standalone, script-free) · JSON · CSV (first table) · **code files** · **Project ZIP**.
- Code blocks are named from the fence (`title="app/main.py"`), a `# file:` comment or the bold line above the block.
  The ZIP contains every file plus `ANSWER.md`; names are sanitised (no `..`, no absolute paths), max 60 files / 8 MB.
- `/zip` = project ZIP of the last answer; `/save app.py <text>` builds any file (no text = first code block).

## 🧠 Smarter, more complete answers
- New **Expert** reply style (Settings → Reply style).
- Core prompt: plan silently, deliver complete work (no "...", "TODO", placeholders), verify before sending,
  ground in web results, length matches the task (the old ~1500-character cap no longer cuts code and analysis).
- Fixed: "Translate" under an answer inside a case now translates that case's last answer.

## Tests
`python -m unittest discover -s tests -t .`  (advertised-command cap raised 6 → 8 for /search and /files).
