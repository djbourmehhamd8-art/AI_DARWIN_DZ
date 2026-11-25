# Architecture

```
Telegram ──getUpdates──▶ BotApp.run ──(bounded queue, 8×workers)──▶ worker threads ──▶ on_message / on_callback
                                                                          │
              ┌───────────────────────────────┬──────────────────────────┴───────────┬──────────────────┐
              ▼                               ▼                                      ▼                  ▼
        commands (/x)                 buttons (m: h: t: …)                   free text → AI          pending input
   security_cmds · proext ·          ui.py + hub.py                          ai_client (stream)     (button asked, next
   extra_cmds · worldtools …         menus, hub, categories                  + web search            message answers it)
              │
              ▼
   pure logic (no Telegram, no I/O): security/*.py, proutils.py, devtools.py   ◀── also used by the web panel (/t, /tools)
```

**Rule: logic is pure and returns data or raises `ValueError`; mixins only format replies.** That is what keeps every
tool unit-testable, fuzzable (`scripts/fuzz.py`) and reusable on the web.

## Adding a tool (5 steps)
1. **Logic** — add a function to `bot/devtools.py` (or a module under `bot/security/`). Take text, return a dict, raise `ValueError("short reason")` on bad input, bound your input (`[:20000]`) and avoid nested quantifiers in regexes.
2. **Registry** — add one tuple to `UTILS` in `bot/utildata.py`: `(kind, icon, Arabic, English, hint_ar, hint_en)`. This alone gives the button prompt, the `t:<kind>` flow and `after` buttons.
3. **Command** — add `cmd_<kind>` (see `bot/extra_cmds.py`; use `self._util_run`, which handles rate limit, errors and the secure-gate).
4. **Hub** — put the kind in one or more `CATEGORIES` in `bot/hub.py` (keywords for search: `SEARCH_KEYWORDS`).
5. **Web + tests** — add the kind to `WEB_TOOLS`/`run_web_tool` in `bot/webext.py` and add tests. `tests/test_v480.py::Registry` fails if any of steps 2–4 is missing.

Then run `make check`.

## Safety defaults
- Secrets: `/pass` and `/secrets` delete the user's message; scanners only ever print masked values; `secrets_guard` redacts logs.
- Input is bounded: local tools get at most 60 000 characters, every parser has its own cap.
- Back-pressure: the update queue is bounded; slow AI answers cannot grow memory.
- Grading: one high-severity finding caps a grade at C, two at D, a fatal one (e.g. SPF `+all`) at F.

## Agent runtime foundation (5.0.0)

`bot/agent_runtime.py` is the first bounded execution layer for the planned multi-agent system.
It accepts only caller-registered `ToolSpec` handlers; it never evaluates model-generated
Python, invokes a shell, or discovers tools dynamically. Plans are capped by step count and
serialized size, arguments and outputs are bounded, execution is sequential, cancellation is
checked between steps, and the total task budget is checked before each tool invocation.
Tools marked `requires_approval=True` are blocked unless the host supplies an approval callback
that explicitly returns true. Tool exceptions are reduced to their type name before being
returned, to avoid leaking provider or credential details.

This is an engine foundation, not yet a Telegram command or autonomous background service.
A future integration must bind each tool to the existing user/group permission model, quotas,
audit trail, and UI approval flow before exposing it to users.

## Release archive policy

Use `make release` (or `python scripts/build_release.py`) instead of manually zipping the
working directory. The builder writes a SHA-256 manifest and excludes secrets, runtime
SQLite files, logs, caches, virtual environments, and runtime data. Only `data/.gitkeep`
is retained to preserve the expected directory. Verify the archive before publishing it.
