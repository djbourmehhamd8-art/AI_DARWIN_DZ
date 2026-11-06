# تشغيل DARWIN DZ على FadeHost (أو أي VPS)

> يعمل البوت على **VPS بصلاحية SSH/root** فقط. لا تستخدم خطة سيرفر ماينكرافت (Multicraft) لأنها لا تدعم بايثون.

## المتطلبات
- نظام **Ubuntu 22.04/24.04** أو **Debian 12** (أي توزيعة بـ `apt`).
- ذاكرة **1 GB** مناسبة (يعمل بـ 512 MB)، ومساحة 5 GB تكفي.
- اتصال صادر فقط (لا تفتح أي منفذ للبوت، فهو يعمل بـ polling).

## التثبيت (10 دقائق)
```bash
# من جهازك: ارفع الأرشيف إلى السيرفر
scp darwin_dz_v4_0_0.zip root@IP_السيرفر:/root/

# على السيرفر
ssh root@IP_السيرفر
apt-get update && apt-get install -y unzip
unzip darwin_dz_v4_0_0.zip && cd darwin_dz
bash deploy/install_vps.sh          # ينشئ مستخدم darwin وبيئة بايثون وخدمة systemd ونسخاً احتياطياً يومياً

nano /opt/darwin_dz/.env            # ضع TELEGRAM_TOKEN و API_KEY (ADMIN_IDS لاحقاً)
sudo -u darwin bash -c 'cd /opt/darwin_dz && venv/bin/python main.py --check'   # فحص الجاهزية
systemctl start darwin
journalctl -u darwin -f             # متابعة السجل (Ctrl+C للخروج)
```
**معرّفك كمدير:** بعد تشغيل البوت أرسل له `/id`، ضع الرقم في `ADMIN_IDS=` داخل `.env`، ثم `systemctl restart darwin`.

## التحقق السريع
`--check` يعرض ✅/⚠️/❌ لكل من: بايثون وSQLite والإعدادات وصلاحيات `.env` والقاعدة والوصول إلى تيليجرام وخادم الذكاء الاصطناعي والبحث. لا يرسل طلبات ذكاء اصطناعي ولا يطبع التوكن.

## المجموعات (مهم)
لتعمل كتابة `DZ سؤالك` في المجموعة يجب أن يقرأ البوت كل الرسائل. افعل **أحد** الأمرين:
1. اجعل البوت **مشرفاً** في المجموعة، أو
2. من @BotFather: `/setprivacy` ← اختر البوت ← **Disable** (ثم أخرج البوت من المجموعة وأضفه من جديد).

إن أضافه **مدير** يُفعَّل تلقائياً، وإلا يصلك زر ✅ تفعيل، أو اكتب `/allowgroup` داخل المجموعة.

## الصيانة اليومية
| المهمة | الأمر |
|---|---|
| حالة البوت | `systemctl status darwin` |
| السجل المباشر | `journalctl -u darwin -f` أو `tail -f /opt/darwin_dz/data/bot.log` |
| إعادة التشغيل | `systemctl restart darwin` |
| إيقاف | `systemctl stop darwin` |
| **تحديث لنسخة جديدة** | ارفع الأرشيف الجديد، فكّه، ثم `bash deploy/install_vps.sh` (لا يمس `.env` ولا `data/` ويعيد التشغيل وحده) |
| نسخة احتياطية يدوية | `sudo -u darwin APP_DIR=/opt/darwin_dz /opt/darwin_dz/deploy/backup.sh` |
| مكان النسخ | `/opt/darwin_dz/data/backups` (يومياً 04:15، تُحفظ 7 أيام) |

## الأمان على السيرفر
```bash
# 1) جدار حماية: SSH فقط
apt-get install -y ufw && ufw allow OpenSSH && ufw --force enable
# 2) مفتاح SSH بدل كلمة المرور (من جهازك): ssh-copy-id root@IP ثم عطّل PasswordAuthentication في /etc/ssh/sshd_config
# 3) حماية من تخمين كلمات المرور (اختياري)
apt-get install -y fail2ban
```
- الخدمة تعمل بمستخدم محدود `darwin` وبعزل systemd؛ لا تكتب إلا في `data/`.
- ملف `.env` وقاعدة البيانات والسجلات بصلاحية `600` تلقائياً. **لا تشارك `.env` أبداً.**

## حل المشاكل
| العَرَض | السبب والحل |
|---|---|
| `Telegram token ❌` | التوكن خاطئ، أو لا يصل السيرفر إلى api.telegram.org (جرّب `curl -I https://api.telegram.org`) |
| `Network → API ❌` | تحقق من `API_BASE_URL` ومن DNS السيرفر (`ping 1.1.1.1`) |
| البوت لا يردّ في المجموعة | Privacy Mode (راجع قسم المجموعات) أو المجموعة غير مفعّلة |
| `.env` تحذير صلاحيات | `chmod 600 /opt/darwin_dz/.env` |
| الخدمة تتوقف فور التشغيل | `journalctl -u darwin -n 50` ثم صحّح السطر المذكور في `.env` |
| لا يوجد systemd (حاوية) | `bash deploy/run_tmux.sh` (يعيد التشغيل تلقائياً داخل tmux) |
