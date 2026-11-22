#!/usr/bin/env bash
# Fallback when the host has no systemd (some containers): run the bot inside tmux.
#   bash deploy/run_tmux.sh        start      |      tmux attach -t darwin      watch      |      tmux kill-session -t darwin   stop
set -euo pipefail
cd "$(dirname "$0")/.."
[ -d venv ] || { python3 -m venv venv; venv/bin/pip install -q -r requirements.txt; }
[ -f .env ] || { cp .env.example .env; chmod 600 .env; echo "edit .env first: nano .env"; exit 1; }
chmod 600 .env; mkdir -p data; chmod 700 data
command -v tmux >/dev/null || { echo "install tmux: apt-get install -y tmux"; exit 1; }
tmux has-session -t darwin 2>/dev/null && { echo "already running: tmux attach -t darwin"; exit 0; }
tmux new-session -d -s darwin "while true; do venv/bin/python main.py; echo 'bot stopped, restarting in 5s'; sleep 5; done"
echo "✅ started in tmux (auto-restarts). Logs: tail -f data/bot.log"
