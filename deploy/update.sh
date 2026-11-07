#!/usr/bin/env bash
# Update the server from your GitHub repository.
#   first time:  git clone https://github.com/YOU/REPO.git /root/darwin_src
#   then:        bash /root/darwin_src/deploy/update.sh
# Keeps .env and data/, takes a database backup first, restarts the bot, then runs the preflight check.
set -euo pipefail
SRC="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR=/opt/darwin_dz
cd "$SRC"
git pull --ff-only
if [ -x "$APP_DIR/deploy/backup.sh" ] && [ -f "$APP_DIR/data/bot.db" ]; then
  APP_DIR="$APP_DIR" sudo -u darwin "$APP_DIR/deploy/backup.sh" || echo "⚠️ backup skipped"
fi
bash "$SRC/deploy/install_vps.sh"
sleep 3
sudo -u darwin bash -c "cd $APP_DIR && venv/bin/python main.py --check" || true
systemctl --no-pager --lines=5 status darwin || true
