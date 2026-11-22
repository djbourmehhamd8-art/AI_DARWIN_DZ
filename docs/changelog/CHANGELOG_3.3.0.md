# DARWIN DZ 3.3.0

## Added
- New `malware` and `cloud` expert personas for reverse engineering / malware triage and AWS/Azure/GCP security reviews.
- Admin `/diag` command and dashboard button. Reports SQLite quick-check, database size, available API-key count, worker count, active replies, uptime, and Python version without exposing credentials.
- Public `Storage.integrity_check()` helper for SQLite diagnostics.

## Fixed / hardened
- AI streaming responses now require a terminal `[DONE]` event or a provider `finish_reason`; incomplete streams raise `APIError` rather than being returned and stored as successful truncated answers.
- Explicit `close()` methods for AI and Telegram HTTP sessions. Main shutdown closes both sessions and SQLite.
- Added regression tests for incomplete streams and SQLite integrity.
- Closed a test-owned SQLite connection that caused `ResourceWarning`.

## Compatibility
- Existing SQLite data, bot commands, personas, provider configuration, and user settings are preserved.
