# DARWIN DZ 3.4.0 — Organisation release

## New: organise your work
- **🗂 Cases** (`/case`): a separate workspace per incident, client or project. Each case has its **own conversation
  and notes**; the model is told which case it is working in. Create, switch, delete (with confirmation), export a
  full case file (`.md`: notes + transcript) or generate a report. Up to 10 cases per user; private chats only.
- **📌 Library** (`/notes`, `/save`): tap **📌 Save** under any answer. Paginated list, view, delete, search
  (wildcard-safe), export all as `.md`. Notes belong to the open case. Secrets are masked before saving.
- **✅ Interactive checklists** (`/checklist`): 8 offline lists — first hour of an incident, ransomware, phishing
  triage, Linux hardening, Windows hardening, cloud baseline, web pre-release, compromised-account recovery.
  Tap to tick; progress bar; reset; save progress to the library. State travels inside the button data
  (no database, nothing to clean up).
- **📄 `/report`**: a structured Markdown report (executive summary, timeline, findings with severity, actions,
  recommendations, open questions) from the open case's conversation and notes. Unknown facts are written as
  "Not established" instead of being invented.
- **👤 My dashboard** (`/me`): persona, style, language, open case, usage, notes/memories/reminders at a glance.

## New: tools
- **🔌 `/port`** — 40+ well-known ports with risk level and hardening advice (numbers, ranges, service names).
- **🕓 `/ts`** — Unix s/ms/µs, Windows FILETIME and WebKit timestamps to UTC (all plausible interpretations),
  ISO date to epoch/FILETIME, `now`.
- **🗺 `/mitre`** — explain an ATT&CK technique for defenders (detections, mitigations).

## Better answers
- Every AI workflow (`/cve /harden /ir /explain /analyze /mitre`) now ships a fixed output layout (verdict line,
  emoji-titled sections, short bullets) so answers look the same every time.
- Buttons under each answer: Retry · Continue · Shorter · Translate · **Save · File** · New · Menu.
- Main menu regrouped by purpose (tools/assistant · cases/library/checklists · chat controls · memory/reminders/
  settings · dashboard/help).

## Reminders
- Compound durations: `1h30m`, `1d 2h`. Friendlier countdowns (`1h 30m`).
- Delivered reminders have **+10m / +1h / ✅ Done** buttons.

## Fixed
- `/broadcast` also reached people who were never authorised (they only pressed /start). It now reaches
  allowed users only.
- A message and its trim are now one SQLite transaction.
- Wiping your data now also removes your cases, case chats and notes.

## Compatibility
- Existing databases migrate automatically (`users.case_id`, new `cases` and `notes` tables).
- All previous commands keep working. Only 6 commands are advertised in Telegram's menu; the rest are shortcuts.

## Verify
```sh
python -m compileall -q .
python -m unittest discover -s tests -t .      # 120 tests
```
