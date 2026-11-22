# DARWIN DZ 4.2.0 — Conversation manners, advanced tools, verified answers

## 💬 Conversation, not only buttons
- **Manners without API cost:** greetings ("السلام عليكم", "hi", "صباح الخير"), thanks and goodbyes get an instant warm reply
  (Islamic greeting answered properly, time-of-day aware, uses the user's name safely). A real question that merely *starts*
  with "hi" still goes to the model.
- **Smart detection:** send a lone **link, hash, CVE id, IP, JWT or domain** and the matching tool runs immediately (`/smart off` to disable).
  Only exact single-artefact messages are routed; a pending button prompt always wins.
- **Style rules for the model:** warm professional tone, mirrors language/dialect, at most one clarifying question, reassurance first
  for victims of an attack, honest about uncertainty. The user's display name is cleaned to one line and labelled *untrusted*
  (a test caught a prompt-injection path through newlines in names — fixed).

## 🎯 More accurate AI
- **CVE grounding:** `/cve` and any message that mentions a CVE id fetch **NVD + CISA KEV + FIRST EPSS** facts (CVSS, dates, CWE,
  "actively exploited?", exploitation probability) and hand them to the model as ground truth. `/cve` also shows a clean card.
  Unknown ids are reported as "not found" instead of invented. Cached 6 h; optional `NVD_API_KEY`.
- **ACCURACY PROTOCOL** in the system prompt: label VERIFIED / KNOWLEDGE / INFERENCE, never invent ids/scores/URLs, name the official
  place to verify, safe-first commands, self-check before answering.
- **✅ Verify** button / `/verify`: a second, independent review pass over the last answer (errors, outdated or invented items,
  unsafe advice) with corrections only where needed.

## 🌐 Advanced defensive tools (passive: DNS, one HTTP/TLS request; no scanning, no exploitation)
- `/domain` — full report: DNS + email authentication + domain age + TLS + security headers + an overall verdict.
- `/dns` (A/AAAA/MX/NS/TXT/CAA, SPF and DMARC findings via DNS-over-HTTPS), `/whois` (RDAP: registrar, **domain age** — under 30 days is a strong phishing indicator),
  `/cert` (issuer, expiry, SANs, TLS version), `/webhead` (HSTS, CSP, clickjacking, nosniff, cookies, server leaks → grade A–F).
- All targets are validated (no IPs/localhost/internal names), connections go only to public addresses pinned to the validated IP, redirects re-validated.
- `/footprint <username>`: which well-known **public** platforms have a handle (19 sites, existence only — never bios, photos or contacts).
  Safeguards: public usernames only (**refuses phone numbers, emails, ID numbers, numeric Telegram IDs**), 6 checks/hour per user, every
  use audited, admin kill-switch `/osint on|off` or `OSINT=false`, and a reminder that a matching name does not prove identity.
  The bot does **not** identify people, resolve Telegram IDs to identities, or search by face/phone/email.

## 📚 Tools & distributions guide
`/toolkit` and the Tools menu: **97 tools in 11 categories** with official links — security Linux distributions (Kali, Parrot, BlackArch,
Security Onion, REMnux, FLARE VM, SIFT, CAINE, Tails, Whonix, Qubes), network, web, DFIR, malware analysis, SOC/SIEM, threat intel,
hardening, DevSecOps, privacy/passwords, learning. `/tool <need>` searches the guide offline and asks the AI to recommend from it.

## Tests
`python -m unittest discover -s tests -t .` — new `tests/test_v42.py` (42 tests). Older tests that used "hello" as a model prompt now use a real question.
