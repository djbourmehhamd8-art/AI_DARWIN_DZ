#!/usr/bin/env bash
# Install or update DARWIN DZ on a Debian/Ubuntu VPS (FadeHost or any other). Run as root from the project folder:
#   sudo bash deploy/install_vps.sh
# Safe to run again for updates: it never overwrites .env or data/.
set -euo pipefail

APP_DIR=/opt/darwin_dz
APP_USER=darwin
SRC="$(cd "$(dirname "$0")/.." && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "❌ run as root:  sudo bash deploy/install_vps.sh"; exit 1; }
command -v apt-get >/dev/null || { echo "❌ this script supports Debian/Ubuntu (apt). See deploy/FADEHOST.md for manual steps."; exit 1; }

echo "▶ installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y -qq
apt-get install -y -qq python3 python3-venv python3-pip ca-certificates cron

id -u "$APP_USER" >/dev/null 2>&1 || useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER"
mkdir -p "$APP_DIR/data"

WAS_ACTIVE=0
if systemctl is-active --quiet darwin 2>/dev/null; then WAS_ACTIVE=1; echo "▶ stopping the running bot"; systemctl stop darwin; fi

if [ "$SRC" != "$APP_DIR" ]; then
  echo "▶ copying files to $APP_DIR"
  tar -C "$SRC" --exclude=./.env --exclude=./data --exclude=./venv --exclude=./tests --exclude='__pycache__' --exclude='*.zip' -cf - . | tar -C "$APP_DIR" -xf -
fi

echo "▶ python environment"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip -q
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt" -q

[ -f "$APP_DIR/.env" ] || { cp "$APP_DIR/.env.example" "$APP_DIR/.env"; NEW_ENV=1; }
chown -R "$APP_USER:$APP_USER" "$APP_DIR"
chmod 750 "$APP_DIR"; chmod 700 "$APP_DIR/data"; chmod 600 "$APP_DIR/.env"
chmod +x "$APP_DIR"/deploy/*.sh

install -m 644 "$APP_DIR/deploy/darwin.service" /etc/systemd/system/darwin.service
# daily database backup at 04:15, kept for 7 days
echo "15 4 * * * $APP_USER APP_DIR=$APP_DIR $APP_DIR/deploy/backup.sh >/dev/null 2>&1" > /etc/cron.d/darwin-backup
chmod 644 /etc/cron.d/darwin-backup
systemctl daemon-reload
systemctl enable darwin >/dev/null 2>&1

if [ "$WAS_ACTIVE" -eq 1 ]; then
  systemctl start darwin
  echo "✅ updated and restarted.  Logs: journalctl -u darwin -f   |  tail -f $APP_DIR/data/bot.log"
else
  echo
  echo "✅ installed. Next steps:"
  echo "   1) nano $APP_DIR/.env          (TELEGRAM_TOKEN, API_KEY, ADMIN_IDS)"
  echo "   2) sudo -u $APP_USER bash -c 'cd $APP_DIR && venv/bin/python main.py --check'     (preflight)"
  echo "   3) systemctl start darwin"
  echo "   4) journalctl -u darwin -f"
fi
