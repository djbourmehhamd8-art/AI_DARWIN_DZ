#!/data/data/com.termux/files/usr/bin/bash
# تشغيل البوت في الخلفية داخل tmux مع منع نوم الجهاز
cd "$(dirname "$0")"
command -v termux-wake-lock >/dev/null && termux-wake-lock
if tmux has-session -t darwin 2>/dev/null; then
  echo "البوت يعمل بالفعل. للمتابعة: tmux attach -t darwin"
  exit 0
fi
tmux new-session -d -s darwin "python main.py"
echo "✅ بدأ البوت. السجل: tail -f data/bot.log  |  للدخول: tmux attach -t darwin"
