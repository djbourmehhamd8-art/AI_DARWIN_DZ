# Security policy

## Reporting a vulnerability
Please **do not open a public issue**. Use GitHub → *Security* → *Report a vulnerability* (private advisory) on this
repository, or message the maintainer on Telegram. Include steps to reproduce and the version (`/start` shows it).
You will get an answer within a few days; fixes are released as a new version with a note in `CHANGELOG.md`.

## Supported versions
Only the latest release receives fixes.

## What the bot does to protect you
- **Access control:** private by default; every admin action is checked on the server (not only hidden), audited, and
  limited to private chats. Moderators cannot touch admins or other moderators.
- **Groups:** a group is answered only after an admin activates it; personal access never opens an inactive group.
- **Secrets:** API keys and tokens never appear in logs; secrets pasted by users are masked before storage or sending to the model.
- **Web fetching:** private/loopback/link-local addresses are refused, the connection is pinned to the validated IP
  (DNS-rebinding safe), redirects are re-validated, sizes and time are capped.
- **Uploads:** ZIP archives are read in memory only (no extraction, no path traversal, zip-bomb limits).
- **Host hardening:** `umask 077`, data folder 700, database/log 600, systemd sandbox in `deploy/darwin.service`.

## For operators
Never commit `.env` or `data/` (the CI refuses it). Rotate the Telegram token and API keys if they ever leak.
Run `python main.py --check` after every change of host or configuration.
