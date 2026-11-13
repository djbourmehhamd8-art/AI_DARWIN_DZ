"""Conversation manners without spending API calls: greetings, thanks and goodbyes, plus a strict router that recognises
a message that is *only* a link, hash, IP, JWT, CVE id or domain and sends it to the matching local tool."""
from __future__ import annotations

import ipaddress
import re
import time

from . import netintel
from .cvedata import CVE_ID

_STRIP = re.compile(r"[^\w\s\u0600-\u06FF]", re.U)
HELLO = {"سلام", "السلام عليكم", "السلام عليكم ورحمه الله", "السلام عليكم ورحمه الله وبركاته", "سلام عليكم", "مرحبا", "مرحبا بك", "اهلا", "اهلا وسهلا",
         "اهلين", "هلا", "هلا والله", "صباح الخير", "مساء الخير", "هاي", "هلو", "السلام", "hi", "hello", "hey", "salam", "good morning",
         "good evening", "good afternoon", "hello there", "hi there", "yo"}
THANKS = {"شكرا", "شكرا لك", "شكرا جزيلا", "جزاك الله خيرا", "بارك الله فيك", "يعطيك العافيه", "تسلم", "ممتاز شكرا", "thanks", "thank you",
          "thx", "ty", "thanks a lot", "many thanks"}
BYE = {"مع السلامه", "وداعا", "الى اللقاء", "تصبح على خير", "bye", "goodbye", "see you", "good night", "cya"}


def clean_name(raw: str) -> str:
    """A display name is attacker-controlled text: keep letters, digits, spaces, dot and hyphen on ONE line, max 24 chars."""
    return " ".join(re.sub(r"[^\w\s.-]", "", raw or "").split())[:24]


def _norm(text: str) -> str:
    s = _STRIP.sub(" ", (text or "").lower())
    s = s.replace("أ", "ا").replace("إ", "ا").replace("آ", "ا").replace("ة", "ه").replace("ى", "ي").replace("ً", "")
    s = re.sub(r"[\u064B-\u065F\u0640]", "", s)
    return " ".join(s.split())


def conversation_kind(text: str):
    """'hello' | 'thanks' | 'bye' | None — only for short, pure pleasantries (never swallows a real question)."""
    s = _norm(text)
    if not s or len(s.split()) > 6:
        return None
    for kind, words in (("hello", HELLO), ("thanks", THANKS), ("bye", BYE)):
        if s in {_norm(w) for w in words}:
            return kind
    return None


def reply(kind: str, lang: str, name: str = "", text: str = "", hour=None) -> str:
    h = time.localtime().tm_hour if hour is None else hour
    nm = f" {name}" if name else ""
    islamic = "السلام" in (text or "")
    if kind == "hello":
        if lang == "ar":
            head = "وعليكم السلام ورحمة الله وبركاته" if islamic else ("صباح النور" if 5 <= h < 12 and "صباح" in text else "مساء النور" if "مساء" in text else "أهلاً بك")
            return (f"{head}{nm} 👋\nأنا <b>DARWIN DZ</b>، مساعدك في الأمن السيبراني. أرسل لي رابطاً أو هاشاً أو رقم CVE أو سجلّاً للتحليل، "
                    "أو اسأل مباشرة، أو افتح القائمة.")
        part = "Good morning" if 5 <= h < 12 else "Good afternoon" if 12 <= h < 18 else "Good evening"
        return (f"{part}{nm} 👋\nI'm <b>DARWIN DZ</b>, your cybersecurity assistant. Send a link, hash, CVE id or log to analyse, "
                "ask a question directly, or open the menu.")
    if kind == "thanks":
        return (f"العفو{nm} 🙏 أنا في الخدمة متى احتجت." if lang == "ar" else f"You're welcome{nm} 🙏 I'm here whenever you need me.")
    return (f"في أمان الله{nm} 👋 ابقَ آمناً." if lang == "ar" else f"Goodbye{nm} 👋 Stay safe.")


_JWT = re.compile(r"^eyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]*$")
_HASH = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{128})$")
_URL = re.compile(r"^(?:https?|hxxps?)(?:://|\[://\])\S+$", re.I)


def smart_route(text: str):
    """(command, args) when the WHOLE message is a single recognisable artefact, else None."""
    s = (text or "").strip()
    if not s or "\n" in s or len(s) > 2000:
        return None
    if _URL.match(s):
        return "url", s
    if _JWT.match(s):
        return "jwt", s
    if _HASH.match(s):
        return "hash", s
    ids = CVE_ID.findall(s)
    if len(ids) == 1 and CVE_ID.fullmatch(s):
        return "cve", s.upper()
    try:
        ipaddress.ip_address(s.strip("[]"))
        return "ip", s
    except ValueError:
        pass
    if re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", s) and netintel.valid_domain(s):
        return "domain", s
    return None
