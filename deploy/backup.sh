#!/usr/bin/env bash
# Consistent SQLite backup (works while the bot is running) + keep 7 days. Needs no sqlite3 CLI.
set -euo pipefail
APP_DIR="${APP_DIR:-/opt/darwin_dz}"
OUT="$APP_DIR/data/backups"
mkdir -p "$OUT"; chmod 700 "$OUT"
STAMP="$(date +%Y%m%d-%H%M)"
"$APP_DIR/venv/bin/python" - "$APP_DIR/data/bot.db" "$OUT/bot-$STAMP.db" <<'PY'
import sqlite3, sys
src, dst = sys.argv[1], sys.argv[2]
a = sqlite3.connect(src, timeout=30)
b = sqlite3.connect(dst)
with b:
    a.backup(b)
a.close(); b.close()
PY
chmod 600 "$OUT/bot-$STAMP.db"
find "$OUT" -name 'bot-*.db' -mtime +7 -delete
echo "backup: $OUT/bot-$STAMP.db"
