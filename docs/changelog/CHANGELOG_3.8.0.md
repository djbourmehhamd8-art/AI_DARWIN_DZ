# DARWIN DZ 3.8.0 — Full audit release

Audit method: static scan (unused code, bare excepts, dangerous calls, SQL building), review of every flow added in
3.5–3.7, edge-case probes, and real local TLS tests for the new fetch path.

## 🐞 Bugs fixed
- **Answer clean-up could delete real content** (3.5.0): "Absolutely not. …" and "Okay so port 22 is open. …" lost
  their first sentence. Only pure pleasantries ("Great question!", "Sure!" with "!") and closers like "I hope this
  helps" are removed now; anything that can be an answer ("Absolutely.", "Certainly not.", "تمام") is never touched.
- **One-shot web flags leaked between updates** because worker threads are reused: a forced `/search` that ended
  early could make the next message search the web. Flags are reset at the start of every update.
- **Coloured buttons could break every keyboard** on a Bot API server that rejects `style`. The bot now detects
  that, resends plain buttons and stops colouring (logged once).
- `/save name.ext⏎text` (newline after the name) was parsed wrongly.
- Admin banned/allowed lists filtered in Python over the whole table; now fixed SQL filters with paging.
- Two unused imports removed.

## 🔐 Security
- **DNS-rebinding hole closed** in web page fetching: the address is validated once and the connection is pinned
  to that exact IP (TLS certificate still verified against the real host name). Proxies/netrc ignored for those
  requests. Verified against a local HTTPS server (match accepted, host-name mismatch rejected).
- Exports (ZIP/TXT/…) now count against the per-user rate limit.

## 🆕 New
- **Send a ZIP of your project** → the bot reads it in memory (never extracts to disk): file tree + text files,
  skips binaries, `node_modules`, `.git`, encrypted entries and `../` paths; refuses zip bombs (entry count,
  unpacked size, bounded reads). Caption = your question.
- **Maintenance mode** (Admin panel → 🛠): everyone except admins gets a short notice; audited.

## Tests
`python -m unittest discover -s tests -t .` — new `tests/test_v38.py` (18 tests).
