# Contributing

1. `make check` must pass (compile, shell syntax, all tests, quick fuzz). CI runs the same on Python 3.9–3.12.
2. New tool? Follow the five steps in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md); the registry test will tell you what is missing.
3. Logic is pure and raises `ValueError`; never let a tool raise another exception type on hostile input.
4. No secrets in code or tests (CI greps for them). Test fixtures use obviously fake values.
5. Bilingual strings (Arabic first, English second) via `tr(lang, ar, en)`.
6. Add a line to `CHANGELOG.md`.
