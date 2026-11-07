# DARWIN DZ 3.2.1 — Reliability and configuration hardening

This maintenance release preserves the existing 3.2 features and adds:

- Startup validation for URLs, worker counts, limits, timeouts, retry counts, temperature, log levels and key strategy. Invalid configuration now fails before the app starts worker threads.
- Defensive Telegram API response parsing, explicit response cleanup, and bounded flood-wait handling.
- Regression tests for invalid configuration and malformed Telegram responses.

## Verify

```sh
python -m compileall -q .
python -m unittest discover -s tests -t .
```

The bot remains intended for authorised defensive security work, lab environments and systems the operator owns or has permission to assess.


## DARWIN DZ 3.2.2 — provider persona and direct expert behavior
- Added `API_PERSONA` selection for the No Restrictions API (`bare`, `notrack`, `concise`, `detailed`, `creative`).
- Default `bare` explicitly uses DARWIN's own expert system prompt instead of the provider's optional persona prompt.
- Reduced unnecessary refusals and repeated warnings for general security education, CTFs, labs, owned systems and authorised testing.
- Kept access control, secret redaction, rate limits, prompt-injection handling and safeguards against unauthorised compromise.
