"""Offline radio-communication helpers: frequency allocations, wavelength/antenna sizes, Morse, phonetic alphabet, Q-codes,
Maidenhead locators, power units, path loss, radio horizon and great-circle distance. Pure functions, no network.
Allocations follow the ITU Region 1 (Europe/Africa/Middle East) at a general level; national rules differ — always check
your regulator before transmitting."""
from __future__ import annotations

import math
import re

C = 299_792_458.0

# (low Hz, high Hz, Arabic name, English name) — specific/narrow entries first is NOT required; lookup sorts by width.
BANDS = [
    (9e3, 150e3, "موجات طويلة جداً/طويلة (إشارات زمن، ملاحة)", "VLF/LF (time signals, navigation)"),
    (153e3, 279e3, "إذاعة موجة طويلة LW", "LW broadcast"),
    (526.5e3, 1606.5e3, "إذاعة موجة متوسطة AM (MW)", "MW AM broadcast"),
    (1.8e6, 2.0e6, "هواة 160 متر", "Amateur 160 m"),
    (3.5e6, 3.8e6, "هواة 80 متر", "Amateur 80 m"),
    (5.9e6, 6.2e6, "إذاعة موجة قصيرة 49 م", "SW broadcast 49 m"),
    (7.0e6, 7.2e6, "هواة 40 متر", "Amateur 40 m"),
    (9.4e6, 9.9e6, "إذاعة موجة قصيرة 31 م", "SW broadcast 31 m"),
    (10.1e6, 10.15e6, "هواة 30 متر", "Amateur 30 m"),
    (11.6e6, 12.1e6, "إذاعة موجة قصيرة 25 م", "SW broadcast 25 m"),
    (13.57e6, 13.87e6, "إذاعة موجة قصيرة 22 م", "SW broadcast 22 m"),
    (14.0e6, 14.35e6, "هواة 20 متر", "Amateur 20 m"),
    (15.1e6, 15.8e6, "إذاعة موجة قصيرة 19 م", "SW broadcast 19 m"),
    (17.48e6, 17.9e6, "إذاعة موجة قصيرة 16 م", "SW broadcast 16 m"),
    (18.068e6, 18.168e6, "هواة 17 متر", "Amateur 17 m"),
    (21.0e6, 21.45e6, "هواة 15 متر", "Amateur 15 m"),
    (24.89e6, 24.99e6, "هواة 12 متر", "Amateur 12 m"),
    (26.965e6, 27.405e6, "نطاق المواطنين CB (11 متر)", "CB radio (11 m)"),
    (28.0e6, 29.7e6, "هواة 10 متر", "Amateur 10 m"),
    (50.0e6, 52.0e6, "هواة 6 متر (تختلف حسب البلد)", "Amateur 6 m (varies by country)"),
    (87.5e6, 108.0e6, "إذاعة FM", "FM broadcast"),
    (108.0e6, 117.975e6, "ملاحة طيران VOR/ILS", "Aviation navigation (VOR/ILS)"),
    (118.0e6, 137.0e6, "اتصالات الطيران المدني (AM)", "Civil aviation voice (AM)"),
    (137.0e6, 138.0e6, "أقمار الطقس القطبية APT/LRPT", "Polar weather satellites APT/LRPT"),
    (144.0e6, 146.0e6, "هواة 2 متر", "Amateur 2 m"),
    (156.0e6, 162.025e6, "اتصالات بحرية VHF", "Marine VHF"),
    (174.0e6, 230.0e6, "تلفزيون/إذاعة رقمية DAB (Band III)", "TV / DAB digital radio (Band III)"),
    (380.0e6, 400.0e6, "اتصالات الطوارئ TETRA (أوروبا)", "TETRA emergency services (Europe)"),
    (430.0e6, 440.0e6, "هواة 70 سم", "Amateur 70 cm"),
    (433.05e6, 434.79e6, "ISM / أجهزة قصيرة المدى 433", "ISM / short-range devices 433"),
    (446.0e6, 446.2e6, "PMR446 (أجهزة لاسلكي ترخيص عام)", "PMR446 licence-free walkie-talkies"),
    (470.0e6, 694.0e6, "تلفزيون UHF", "UHF television"),
    (791.0e6, 862.0e6, "LTE (نطاق 800)", "LTE band 800"),
    (863.0e6, 870.0e6, "أجهزة قصيرة المدى 868 / LoRa أوروبا", "SRD 868 / LoRa Europe"),
    (876.0e6, 960.0e6, "GSM 900 / LTE 900", "GSM 900 / LTE 900"),
    (1710e6, 1880e6, "GSM 1800 / LTE 1800", "GSM 1800 / LTE 1800"),
    (1164e6, 1300e6, "ملاحة عبر الأقمار GNSS (L5/L2)", "GNSS navigation (L5/L2)"),
    (1559e6, 1610e6, "ملاحة عبر الأقمار GNSS (L1)", "GNSS navigation (L1)"),
    (1920e6, 2170e6, "3G UMTS", "3G UMTS"),
    (2400e6, 2483.5e6, "Wi-Fi / Bluetooth / ZigBee 2.4 GHz", "Wi-Fi / Bluetooth / ZigBee 2.4 GHz"),
    (5150e6, 5875e6, "Wi-Fi 5 GHz", "Wi-Fi 5 GHz"),
    (5925e6, 7125e6, "Wi-Fi 6E (6 GHz)", "Wi-Fi 6E (6 GHz)"),
]

# exact/notable frequencies (Hz, tolerance Hz, Arabic, English)
SPECIAL = [
    (121.5e6, 5e3, "تردد استغاثة الطيران المدني", "Civil aviation distress (guard)"),
    (243.0e6, 5e3, "تردد استغاثة عسكري", "Military distress (guard)"),
    (406.0e6, 0.2e6, "منارات الاستغاثة EPIRB/ELT/PLB (406 MHz)", "Distress beacons EPIRB/ELT/PLB (406 MHz)"),
    (156.8e6, 5e3, "قناة 16 البحرية: نداء واستغاثة", "Marine channel 16: calling & distress"),
    (156.525e6, 5e3, "قناة 70 البحرية: نداء انتقائي رقمي DSC", "Marine channel 70: digital selective calling (DSC)"),
    (161.975e6, 5e3, "نظام تعريف السفن AIS 1", "Ship tracking AIS 1"),
    (162.025e6, 5e3, "نظام تعريف السفن AIS 2", "Ship tracking AIS 2"),
    (1090e6, 1e6, "طائرات ADS-B (1090ES / Mode S)", "Aircraft ADS-B (1090ES / Mode S)"),
    (978e6, 1e6, "ADS-B UAT (الولايات المتحدة)", "ADS-B UAT (United States)"),
    (144.8e6, 5e3, "APRS في أوروبا/أفريقيا", "APRS in Europe/Africa"),
    (145.8e6, 5e3, "المحطة الدولية ISS: صوت/تلفزيون هواة", "ISS amateur voice / SSTV"),
    (145.825e6, 5e3, "ISS APRS الرقمي", "ISS APRS digipeater"),
    (137.1e6, 5e3, "أقمار METEOR-M LRPT", "METEOR-M LRPT satellites"),
    (137.62e6, 5e3, "NOAA 15 APT", "NOAA 15 APT"),
    (137.9125e6, 5e3, "NOAA 18/19 APT", "NOAA 18/19 APT"),
    (1575.42e6, 0.5e6, "GPS L1 C/A", "GPS L1 C/A"),
    (1227.6e6, 0.5e6, "GPS L2", "GPS L2"),
    (1176.45e6, 0.5e6, "GPS L5", "GPS L5"),
    (1694.1e6, 0.5e6, "أقمار الطقس الثابتة (HRIT/LRIT)", "Geostationary weather satellites (HRIT/LRIT)"),
    (433.92e6, 0.2e6, "مفاتيح/حساسات لاسلكية شائعة 433", "Common 433 MHz remotes/sensors"),
    (868.3e6, 0.2e6, "LoRa/حساسات 868", "LoRa / sensors 868"),
    (27.185e6, 5e3, "CB القناة 19", "CB channel 19"),
    (446.00625e6, 3e3, "PMR446 القناة 1", "PMR446 channel 1"),
    (14.2e6, 5e3, "هواة 20 م: نداء/مكالمات دولية", "Amateur 20 m: DX calling area"),
    (7.1e6, 5e3, "هواة 40 م: مكالمات", "Amateur 40 m: voice area"),
    (125e3, 5e3, "RFID منخفض التردد 125 kHz", "Low-frequency RFID 125 kHz"),
    (13.56e6, 50e3, "RFID/NFC 13.56 MHz", "RFID / NFC 13.56 MHz"),
]

_UNITS = {"hz": 1.0, "khz": 1e3, "mhz": 1e6, "ghz": 1e9, "k": 1e3, "m": 1e6, "g": 1e9}


def parse_freq(text: str):
    """'145.5 MHz', '7100kHz', '2.4ghz', '1090' (bare numbers are MHz) -> Hz, or None."""
    m = re.fullmatch(r"\s*([0-9]+(?:[.,][0-9]+)?)\s*([a-zA-Z]{0,3})\s*", text or "")
    if not m:
        return None
    unit = (m.group(2) or "mhz").lower()
    if unit not in _UNITS:
        return None
    hz = float(m.group(1).replace(",", ".")) * _UNITS[unit]
    return hz if 1e3 <= hz <= 3e11 else None


def fmt_freq(hz: float) -> str:
    for div, unit in ((1e9, "GHz"), (1e6, "MHz"), (1e3, "kHz")):
        if hz >= div:
            return f"{hz / div:.6g} {unit}"
    return f"{hz:.6g} Hz"


def lookup(hz: float) -> dict:
    """Allocations that contain the frequency (narrowest first) and notable frequencies within tolerance."""
    inside = sorted(((hi - lo, ar, en) for lo, hi, ar, en in BANDS if lo <= hz <= hi), key=lambda x: x[0])
    special = [(ar, en) for f, tol, ar, en in SPECIAL if abs(hz - f) <= tol]
    return {"bands": [(ar, en) for _, ar, en in inside], "special": special}


def wavelength(hz: float) -> dict:
    lam = C / hz
    return {"lambda_m": lam, "half": lam / 2, "quarter": lam / 4,
            "dipole_m": 468.0 / (hz / 1e6) * 0.3048,           # classic half-wave dipole rule (468/f MHz feet), end-effect included
            "vertical_m": 234.0 / (hz / 1e6) * 0.3048}


# ------------------------------------------------------------------------------------------ Morse / phonetic
MORSE = {"A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.", "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-",
         "L": ".-..", "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-", "U": "..-", "V": "...-",
         "W": ".--", "X": "-..-", "Y": "-.--", "Z": "--..", "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-", "5": ".....",
         "6": "-....", "7": "--...", "8": "---..", "9": "----.", ".": ".-.-.-", ",": "--..--", "?": "..--..", "'": ".----.", "!": "-.-.--",
         "/": "-..-.", "(": "-.--.", ")": "-.--.-", "&": ".-...", ":": "---...", ";": "-.-.-.", "=": "-...-", "+": ".-.-.", "-": "-....-",
         "_": "..--.-", '"': ".-..-.", "$": "...-..-", "@": ".--.-."}
_REV = {v: k for k, v in MORSE.items()}
PROSIGNS = {"SOS": "...---...", "AR": ".-.-.", "SK": "...-.-", "BT": "-...-", "KN": "-.--."}


def to_morse(text: str) -> str:
    words = []
    for w in (text or "").upper().split():
        words.append(" ".join(MORSE[c] for c in w if c in MORSE))
    return " / ".join(x for x in words if x)


def from_morse(code: str) -> str:
    out = []
    for word in re.split(r"\s*/\s*|\s{3,}", (code or "").strip()):
        letters = [_REV.get(sym, "?") for sym in word.split()]
        if letters:
            out.append("".join(letters))
    return " ".join(out)


def looks_like_morse(text: str) -> bool:
    return bool(text) and bool(re.fullmatch(r"[.\-/\s·–−]+", text)) and any(c in text for c in ".-·")


NATO = {"A": "Alfa", "B": "Bravo", "C": "Charlie", "D": "Delta", "E": "Echo", "F": "Foxtrot", "G": "Golf", "H": "Hotel", "I": "India",
        "J": "Juliett", "K": "Kilo", "L": "Lima", "M": "Mike", "N": "November", "O": "Oscar", "P": "Papa", "Q": "Quebec", "R": "Romeo",
        "S": "Sierra", "T": "Tango", "U": "Uniform", "V": "Victor", "W": "Whiskey", "X": "X-ray", "Y": "Yankee", "Z": "Zulu",
        "0": "Zero", "1": "Wun", "2": "Too", "3": "Tree", "4": "Fower", "5": "Fife", "6": "Six", "7": "Seven", "8": "Ait", "9": "Niner"}


def phonetic(text: str) -> str:
    return " · ".join(NATO[c] for c in (text or "").upper() if c in NATO)


QCODES = {
    "QRA": ("اسم محطتك؟ / اسم محطتي هو…", "What is the name of your station? / My station is…"),
    "QRG": ("ترددك الدقيق؟", "Your exact frequency?"),
    "QRK": ("وضوح إشاراتك (1–5)", "Readability of your signals (1–5)"),
    "QRL": ("هل التردد مشغول؟ / التردد مشغول", "Is the frequency busy? / The frequency is busy"),
    "QRM": ("تداخل من محطات أخرى (صناعي)", "Man-made interference"),
    "QRN": ("تشويش جوّي طبيعي", "Natural (atmospheric) noise"),
    "QRO": ("ارفع القدرة", "Increase power"),
    "QRP": ("اخفض القدرة (تشغيل بقدرة منخفضة)", "Reduce power (low-power operation)"),
    "QRQ": ("أرسل أسرع", "Send faster"),
    "QRS": ("أرسل أبطأ", "Send slower"),
    "QRT": ("أوقف الإرسال", "Stop transmitting"),
    "QRU": ("لا شيء لك", "I have nothing for you"),
    "QRV": ("أنا جاهز", "I am ready"),
    "QRX": ("انتظر / سأناديك لاحقاً", "Stand by / I will call you again"),
    "QRZ": ("من ينادي؟", "Who is calling me?"),
    "QSA": ("قوة إشاراتك (1–5)", "Strength of your signals (1–5)"),
    "QSB": ("إشارتك تضعف وتقوى (تلاشي)", "Your signals are fading"),
    "QSK": ("يمكنني سماعك بين إشاراتي (كسر إرسال)", "I can hear you between my signals (break-in)"),
    "QSL": ("أؤكد الاستلام / بطاقة تأكيد", "I acknowledge receipt / confirmation card"),
    "QSO": ("اتصال بين محطتين", "A contact between two stations"),
    "QSP": ("أبلغ الرسالة لآخر", "Relay a message"),
    "QSY": ("غيّر التردد", "Change frequency"),
    "QTC": ("لدي رسائل لإرسالها", "I have messages to send"),
    "QTH": ("موقعي / موقعك؟", "My / your location"),
    "QTR": ("الوقت الدقيق", "The exact time"),
    "QNH": ("ضغط المعايرة لقراءة الارتفاع فوق سطح البحر", "Altimeter setting that reads elevation above sea level"),
    "QFE": ("الضغط عند ارتفاع المطار (يقرأ الارتفاع صفراً عند الهبوط)", "Pressure at aerodrome elevation (altimeter reads 0 on landing)"),
    "QNE": ("الضغط القياسي 1013.25 hPa (مستويات الطيران FL)", "Standard pressure 1013.25 hPa (flight levels)"),
}


# ------------------------------------------------------------------------------------------ Maidenhead locator
def to_grid(lat: float, lon: float, pairs: int = 3) -> str:
    lon, lat = lon + 180.0, lat + 90.0
    loc = chr(ord("A") + int(lon // 20)) + chr(ord("A") + int(lat // 10))
    lon, lat = lon % 20, lat % 10
    loc += str(int(lon // 2)) + str(int(lat // 1))
    lon, lat = (lon % 2) * 12, (lat % 1) * 24
    if pairs >= 3:
        loc += chr(ord("a") + int(lon)) + chr(ord("a") + int(lat))
    return loc


def from_grid(loc: str):
    s = (loc or "").strip()
    if not re.fullmatch(r"[A-Ra-r]{2}[0-9]{2}([A-Xa-x]{2})?", s):
        return None
    s = s.upper()
    lon = (ord(s[0]) - 65) * 20 - 180 + int(s[2]) * 2
    lat = (ord(s[1]) - 65) * 10 - 90 + int(s[3])
    if len(s) == 6:
        lon += (ord(s[4]) - 65) / 12 + 1 / 24
        lat += (ord(s[5]) - 65) / 24 + 1 / 48
    else:
        lon += 1
        lat += 0.5
    return round(lat, 4), round(lon, 4)


# ------------------------------------------------------------------------------------------ units and link maths
def parse_power(text: str):
    """'30dBm', '1 W', '500mW', '-100 dBm', '20dBW' -> watts, or None."""
    m = re.fullmatch(r"\s*(-?[0-9]+(?:[.,][0-9]+)?)\s*(dbm|dbw|mw|uw|µw|w|kw)?\s*", (text or "").lower())
    if not m:
        return None
    v, u = float(m.group(1).replace(",", ".")), m.group(2) or "w"
    watts = {"dbm": lambda x: 10 ** (x / 10) / 1000, "dbw": lambda x: 10 ** (x / 10), "mw": lambda x: x / 1e3, "uw": lambda x: x / 1e6,
             "µw": lambda x: x / 1e6, "w": lambda x: x, "kw": lambda x: x * 1e3}[u](v)
    return watts if watts > 0 else None


def power_table(watts: float) -> dict:
    return {"W": watts, "mW": watts * 1e3, "dBm": 10 * math.log10(watts * 1e3), "dBW": 10 * math.log10(watts)}


def fspl_db(freq_hz: float, dist_km: float) -> float:
    """Free-space path loss in dB: 20log10(d_km) + 20log10(f_MHz) + 32.44."""
    return 20 * math.log10(dist_km) + 20 * math.log10(freq_hz / 1e6) + 32.44


def radio_horizon_km(h1_m: float, h2_m: float = 0.0) -> float:
    """Radio line-of-sight with standard atmospheric refraction (k = 4/3): 4.12 * (sqrt(h1) + sqrt(h2)) km."""
    return 4.12 * (math.sqrt(max(h1_m, 0)) + math.sqrt(max(h2_m, 0)))


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    a = math.sin((p2 - p1) / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(math.radians(lon2 - lon1) / 2) ** 2
    return 2 * 6371.0088 * math.asin(min(1.0, math.sqrt(a)))


def bearing_deg(lat1, lon1, lat2, lon2) -> float:
    p1, p2, dl = math.radians(lat1), math.radians(lat2), math.radians(lon2 - lon1)
    y = math.sin(dl) * math.cos(p2)
    x = math.cos(p1) * math.sin(p2) - math.sin(p1) * math.cos(p2) * math.cos(dl)
    return (math.degrees(math.atan2(y, x)) + 360) % 360


def compass(deg: float) -> str:
    return ["N", "NNE", "NE", "ENE", "E", "ESE", "SE", "SSE", "S", "SSW", "SW", "WSW", "W", "WNW", "NW", "NNW"][int((deg % 360) / 22.5 + 0.5) % 16]


def parse_latlon(text: str):
    m = re.fullmatch(r"\s*(-?[0-9]{1,2}(?:\.[0-9]+)?)\s*[, ]\s*(-?[0-9]{1,3}(?:\.[0-9]+)?)\s*", text or "")
    if not m:
        return None
    lat, lon = float(m.group(1)), float(m.group(2))
    return (lat, lon) if -90 <= lat <= 90 and -180 <= lon <= 180 else None
