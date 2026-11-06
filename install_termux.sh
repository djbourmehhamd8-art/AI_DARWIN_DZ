#!/data/data/com.termux/files/usr/bin/bash
# تثبيت المتطلبات على Termux
set -e
pkg update -y
pkg install -y python tmux termux-api
pip install -r requirements.txt
[ -f .env ] || cp .env.example .env
chmod 600 .env 2>/dev/null || true   # الملف يحوي التوكن ومفتاح API
chmod +x start.sh stop.sh 2>/dev/null || true
echo "✅ تم. عدّل الإعدادات: nano .env  ثم شغّل: ./start.sh"
