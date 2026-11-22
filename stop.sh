#!/data/data/com.termux/files/usr/bin/bash
tmux kill-session -t darwin 2>/dev/null && echo "⏹ تم الإيقاف" || echo "البوت غير شغال"
command -v termux-wake-unlock >/dev/null && termux-wake-unlock
