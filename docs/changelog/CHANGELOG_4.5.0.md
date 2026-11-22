# 4.5.0 — AI chat on the web, extra tools

## Web panel
- New navigation: Users · AI chat · Tools · Audit · System.
- `/chat`: talk to the AI from the browser, pick a persona, clear the conversation. History lives only in the login session
  (never in the database), is capped, rate-limited (12 messages/minute) and everything is HTML-escaped. No JavaScript needed.
- `/tools`: the offline tools below, in the browser.
- `/audit`: last 150 audit entries. `/system`: version, uptime, model, API key health.
- Request body limit raised so long Arabic messages fit.

## Telegram
- Main menu: new buttons "🧮 Extra tools" and "🌐 AI chat (web)" (opens the web chat for the admin; explains setup otherwise).
- 13 new tools, each a button and a command: /calc /unit /pct /json /regex /textstat /uniq /urlenc /color /caseconv /slug /roll /uuid, plus /webchat.
- The calculator never uses `eval` (AST whitelist, size limits); the regex tester rejects patterns that can hang the bot.

Tests: tests/test_v450.py.
