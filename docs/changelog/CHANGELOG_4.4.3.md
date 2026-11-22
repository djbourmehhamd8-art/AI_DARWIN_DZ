# 4.4.3 — Security & correctness audit fixes

## Security
- **Secrets no longer sent to the AI provider.** `Config.ai_keys()` returns only AI keys; the AI client no longer receives the
  Brave key, NVD key or `WEB_PANEL_TOKEN` (`all_keys()` is now documented as log-redaction only).
  `validate()` now reports a missing `API_KEY` even when other secrets are set.
- **Web panel login lockout can no longer be bypassed** with a forged `X-Forwarded-For`: the header is trusted only when the
  TCP peer is the local reverse proxy. The lockout table is pruned instead of being wiped when it fills up.
- Web panel: socket timeout (slowloris), connection closed after a 413, non-ASCII CSRF values answer 403 (was 500).
- Untrusted web/CVE text is added to the user's turn inside a labelled `<reference_data>` block instead of the system
  message after `SAFETY_TAIL`.
- SSRF guard also refuses IPv4-compatible (`::a.b.c.d`) and NAT64 (`64:ff9b::/96`) addresses.

## Fixes
- Daily quota is re-checked inside the chat lock: a burst of messages can no longer exceed the limit.
- `/retry` refused by quota/rate limit no longer deletes the previous AI answer from the history.
- Web panel shows the last page instead of an empty table when the requested page is out of range.
- `.env`: trailing ` # comment` and `export KEY=...` are handled.
- Web panel search lower-cases ASCII only, matching SQLite `LOWER()`.
