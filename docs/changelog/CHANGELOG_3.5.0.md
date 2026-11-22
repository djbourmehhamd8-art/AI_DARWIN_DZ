# DARWIN DZ 3.5.0 — Answer quality release

## Better answers
- New **ANSWER QUALITY** block in the core prompt: verdict first, no filler, decisive single best recommendation,
  severity-ordered findings, priority-ordered actions, explicit `🧭 Confidence` line when evidence is incomplete,
  "not established" instead of invented facts, one stated assumption instead of many questions.
- `tidy_answer()` removes chatty openers ("Sure!", "بالتأكيد!") and closers ("I hope this helps", "لا تتردد...")
  from every rendered answer. It never touches code blocks and never empties a reply.

## Verify
```sh
python -m compileall -q .
python -m unittest discover -s tests -t .
```
