# رفع التحديث إلى GitHub

```bash
# داخل مجلد المشروع على جهازك (بعد فك الأرشيف فوق نسختك القديمة)
git status                         # تأكد أن .env و data/ لا تظهر (يجب أن تكون مستثناة)
git add -A
git commit -m "v4.1.0: strict group authorisation, daily limits, resilient web search, GitHub CI"
git tag v4.1.0
git push origin main --tags        # غيّر main إلى اسم فرعك
```
- بعد الرفع تعمل GitHub Actions تلقائياً (تبويب **Actions**). يجب أن يكون الأخضر على كل إصدارات بايثون.
- لإصدار رسمي: GitHub → Releases → Draft a new release → اختر الوسم `v4.1.0` والصق نص `docs/changelog/CHANGELOG_4.1.0.md`.
- على السيرفر: `bash /root/darwin_src/deploy/update.sh` (يسحب آخر نسخة ويعيد التشغيل ويفحص الجاهزية).
- إن كان `.env` أو قاعدة بيانات قد رُفعت سابقاً: **غيّر التوكن والمفاتيح فوراً** (حذف الملف لا يمسح التاريخ).
