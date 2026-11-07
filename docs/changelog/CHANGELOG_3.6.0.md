# DARWIN DZ 3.6.0 — Admin panel, colours, security fix

## 🔐 Security fix
- **Admin commands no longer run in groups.** Before, an admin sending `/backup` inside a group posted the whole
  database (every user's conversations) into that group; `/users`, `/audit`, `/keys` leaked the same way.
  Now admin commands, admin buttons and the backup function refuse any chat with a negative id.
- Admins can no longer ban/disallow other admins, themselves, or invalid (<= 0) IDs.
- Ban and "clear chat" from the panel need a confirmation step; every action is written to the audit log.

## 👑 New admin panel
- Dashboard with live numbers (users, active 24h, banned, messages, keys, uptime, access mode).
- **Users**: paged list (8 per page), filters for Banned / Allowed, one button per user.
- **User card**: status, usage, last seen + Ban/Unban, Allow/Disallow, Clear chat buttons.
- **Find user** by ID or @username (`/find` or the button).
- **System** screen: SQLite integrity, DB size, API keys, running replies, reminders, model, uptime.

## 🎨 Colours and quotes
- Buttons are coloured through Telegram's `style` field: red = danger (ban, cancel, stop), green = confirm/allow,
  blue = navigation. Set `BUTTON_COLORS=0` to switch off.
- Answers colour meaning with 🔴🟠🟡🟢🔵 severity markers, put the verdict in a quote, and long quotes
  (4+ lines) become collapsible `blockquote expandable`.

## Verify
```sh
python -m unittest discover -s tests -t .
```
