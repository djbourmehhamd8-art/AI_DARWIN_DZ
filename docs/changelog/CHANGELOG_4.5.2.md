# 4.5.2 — Bug-fix pass

## Fixed
- **Commands followed by a newline** (`/remember⏎text`, `/remind⏎10m⏎text`, `/dm⏎id⏎text`, `/ban⏎id`) were answered with "unknown command": arguments are now split on any whitespace. Multi-line arguments keep their inner line breaks.
- **Oversized or look-alike numbers** (`/unremind 99999999999999999999`, `/forget ²`, `/ban 99999999999999999999`, `/case go …`, `/dm …`) raised `OverflowError`/`ValueError` inside the worker: the user got no reply and the log got a traceback. All user-typed numbers now go through `utils.safe_int` (never raises, bounded to what SQLite can store) and the user gets the usage message.
- `ADMIN_IDS` / `ALLOWED_IDS` containing `--5` or `²` crashed start-up with `ValueError`; invalid entries are now ignored.
- `find_user` and the web-panel search crashed on `--5`, `²` or very long digit strings.
- `/remind` with a duration of thousands of digits raised `ValueError` (Python's 4300-digit limit); durations are limited to 10 digits per unit.
- `.env`: a UTF-8 BOM (common from phone/Windows editors) renamed the first key, so e.g. `TELEGRAM_TOKEN` was "missing"; a comment after a quoted value (`KEY="a b"  # note`) leaked into the value. Both fixed.
- `_bool("  ", default)` returned `False` instead of the default for whitespace-only values.
- Uploaded ZIP: one corrupt member (bad CRC) or an unsupported compression method (Deflate64) aborted the whole archive silently; such members are now skipped and counted, and entries are closed properly.
- `Storage.add_fact`: the limit check and insert are now atomic, so concurrent `/remember` calls cannot exceed the per-user limit.

## Docs
- README title said v4.4.2 and the test count said ~70; both corrected.

Tests: `tests/test_v452.py` (12 tests).
