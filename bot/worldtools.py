"""World tools: live aircraft radar, aviation & general weather, ISS, space weather for HF radio, earthquakes, internet radio,
radio-communication calculators, passive network intelligence and a gallery of live web portals."""
from __future__ import annotations

import html
import re
import time

from . import netintel, portals, radiotools as R, skytools as S
from .render import Typing
from .ui import kb, tr

SAFETY = ("ℹ️ بيانات مجتمعية من مستقبلات ADS-B؛ التغطية متفاوتة وقد تتأخر أو تنقص. للاطلاع فقط، لا للملاحة أو السلامة.",
          "ℹ️ Crowd-sourced ADS-B data: coverage varies and may be delayed or incomplete. For information only, never for navigation or safety.")


def _e(x) -> str:
    return html.escape(str(x if x is not None else ""), quote=False)


def _plain(h: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", h))


def _alt(a: dict) -> str:
    if a["ground"]:
        return "🛬 ground"
    if a["alt_ft"] is None:
        return "—"
    return f"FL{a['alt_ft'] // 100:03d}" if a["alt_ft"] >= 18000 else f"{a['alt_ft']} ft"


def aircraft_line(i, a: dict, lang: str, show_pos: bool = False) -> str:
    emg = S.EMERGENCY.get(a["squawk"])
    name = _e(a["call"] or a["reg"] or a["hex"].upper())
    parts = [f"<b>{name}</b>", _e(a["type"] or "?"), _alt(a)]
    if a["gs"] is not None:
        parts.append(f"{round(a['gs'])} kt")
    if a["track"] is not None:
        parts.append(f"{round(a['track']):03d}°")
    if a["dist_km"] is not None:
        parts.append(f"{a['dist_km']:.0f} km {R.compass(a['bearing'])}")
    if show_pos and a["lat"] is not None:
        parts.append(f"{a['lat']:.2f},{a['lon']:.2f}")
    mark = f"🚨 {tr(lang, S.EMERGENCY[a['squawk']][1], S.EMERGENCY[a['squawk']][0])} " if emg else ""
    prefix = f"{i}. " if i else ""
    return f"{prefix}{mark}" + " · ".join(parts) + (f" · <code>{_e(a['hex'])}</code>" if not a["call"] or show_pos else "")


class WorldToolsMixin:
    def world_commands(self) -> dict:
        names = ["radar", "flight", "plane", "squawk", "metar", "weather", "iss", "space", "quakes", "radio", "freq", "wave", "morse",
                 "phonetic", "qcode", "grid", "power", "fspl", "horizon", "dist", "subdomains", "asn", "rdns", "mac", "exposure",
                 "portals", "world", "rf"]
        return {n: getattr(self, f"cmd_{n}") for n in names}

    # ------------------------------------------------------------------ shared
    def _open_btn(self, chat_id, text: str, url: str):
        """Inside Telegram (Mini App) in private chats when allowed; a normal link otherwise."""
        return (text, ("webapp:" + url) if chat_id > 0 and self.cfg.webapp_buttons else url)

    def _gate(self, chat_id, user, args: str, ar: str, en: str, need_args: bool = True) -> bool:
        if need_args and not args.strip():
            self.tg.send_message(chat_id, tr(user["lang"], ar, en))
            return False
        return self._sec_gate(chat_id, user)

    def _fail(self, chat_id, user, ar: str = "تعذّر جلب البيانات الآن (قد تكون الخدمة مشغولة). حاول بعد قليل.",
              en: str = "Could not fetch the data right now (the service may be busy). Try again shortly.") -> None:
        self.tg.send_message(chat_id, "⚠️ " + tr(user["lang"], ar, en))

    def _place(self, chat_id, user, text: str):
        g = S.geocode(text)
        if not g:
            self.tg.send_message(chat_id, "🔍 " + tr(user["lang"], "لم أجد هذا المكان. جرّب اسم مدينة أو إحداثيات مثل 36.75,3.06.",
                                                      "Place not found. Try a city name or coordinates like 36.75,3.06."))
        return g

    # ================================================================== aircraft
    def cmd_radar(self, chat_id, user, args):
        lang = user["lang"]
        if not self._gate(chat_id, user, args, "✈️ /radar مدينة [نصف القطر كم] — مثال: /radar Algiers 80 أو /radar 36.75,3.06",
                          "✈️ /radar city [radius km] — e.g. /radar Algiers 80 or /radar 36.75,3.06"):
            return
        parts = args.strip().rsplit(None, 1)
        radius = 60.0
        if len(parts) == 2 and re.fullmatch(r"\d{1,3}", parts[1]) and not R.parse_latlon(args):
            radius, args = float(parts[1]), parts[0]
        radius = min(max(radius, 5.0), 400.0)
        place = self._place(chat_id, user, args)
        if not place:
            return
        with Typing(self.tg, chat_id):
            res = S.aircraft_near(place["lat"], place["lon"], radius)
        if not res["ok"]:
            return self._fail(chat_id, user)
        ac, shown = res["aircraft"], res["aircraft"][:12]
        self.db.add_audit(user["id"], "radar", place["name"][:40])
        head = f"✈️ <b>{tr(lang, 'رادار الطائرات', 'Aircraft radar')}</b> — {_e(place['name'])}{(', ' + _e(place['country'])) if place['country'] else ''}"
        lines = [head, f"<blockquote>{len(ac)} {tr(lang, 'طائرة ضمن', 'aircraft within')} {res['radius_km']:.0f} km · {_e(res['provider'])} · "
                       f"{time.strftime('%H:%M:%S UTC', time.gmtime())}</blockquote>"]
        if ac:
            lines.append("<pre>" + _e(S.radar_scope(ac, res["radius_km"])) + "</pre>")
            lines.append("<blockquote expandable>" + "\n".join(aircraft_line(i, a, lang) for i, a in enumerate(shown, 1)) + "</blockquote>")
            emerg = [a for a in ac if a["squawk"] in S.EMERGENCY]
            for a in emerg[:3]:
                lines.append("🚨 " + aircraft_line(0, a, lang))
        else:
            lines.append(tr(lang, "لا طائرات مرصودة الآن في هذا النطاق (قد تكون التغطية ضعيفة).", "No aircraft seen in this area right now (coverage may be thin)."))
        lines.append("<i>" + tr(lang, *SAFETY) + "</i>")
        self._send(chat_id, lines, kb([[self._open_btn(chat_id, "🗺 " + tr(lang, "افتح الخريطة الحية", "Open the live map"), portals.portal_url(place["lat"], place["lon"]))]]))

    def _aircraft_list(self, chat_id, user, kind: str, value: str, title: str):
        lang = user["lang"]
        with Typing(self.tg, chat_id):
            res = S.aircraft_lookup(kind, value)
        if not res["ok"]:
            return self._fail(chat_id, user, "قيمة غير صالحة أو الخدمة غير متاحة.", "Invalid value or the service is unavailable.") if res.get("error") != "invalid" else \
                self.tg.send_message(chat_id, "⚠️ " + tr(lang, "قيمة غير صالحة.", "Invalid value."))
        ac = res["aircraft"]
        self.db.add_audit(user["id"], f"aircraft_{kind}", value[:12])
        lines = [f"✈️ <b>{_e(title)}</b> — <code>{_e(value.upper())}</code>"]
        if ac:
            lines.append("<blockquote>" + "\n".join(aircraft_line(i, a, lang, show_pos=True) for i, a in enumerate(ac[:8], 1)) + "</blockquote>")
            a0 = next((a for a in ac if a["lat"] is not None), None)
            markup = kb([[self._open_btn(chat_id, "🗺 " + tr(lang, "على الخريطة", "On the map"), f"https://globe.adsbexchange.com/?icao={a0['hex']}")]]) if a0 else None
        else:
            lines.append(tr(lang, "غير مرصودة الآن (ربما على الأرض خارج التغطية أو لا تبثّ).", "Not seen right now (possibly on the ground or not transmitting)."))
            markup = None
        lines.append("<i>" + tr(lang, *SAFETY) + "</i>")
        self._send(chat_id, lines, markup)

    def cmd_flight(self, chat_id, user, args):
        if self._gate(chat_id, user, args, "🛩 /flight رمز_الرحلة — مثال: /flight AH1001", "🛩 /flight callsign — e.g. /flight AH1001"):
            self._aircraft_list(chat_id, user, "callsign", args.strip().split()[0], tr(user["lang"], "رحلة", "Flight"))

    def cmd_plane(self, chat_id, user, args):
        if not self._gate(chat_id, user, args, "🛩 /plane رقم_التسجيل أو hex — مثال: /plane 7T-VJA أو /plane 0a1b2c", "🛩 /plane registration or hex — e.g. /plane 7T-VJA or /plane 0a1b2c"):
            return
        v = args.strip().split()[0]
        self._aircraft_list(chat_id, user, "hex" if re.fullmatch(r"[0-9a-fA-F]{6}", v) else "reg", v, tr(user["lang"], "طائرة", "Aircraft"))

    def cmd_squawk(self, chat_id, user, args):
        lang = user["lang"]
        if not self._gate(chat_id, user, args, "", "", need_args=False):
            return
        found = []
        with Typing(self.tg, chat_id):
            for code in (["7700", "7600", "7500"] if not args.strip() else [args.strip().split()[0]]):
                r = S.aircraft_lookup("squawk", code)
                if r["ok"]:
                    found += [(code, a) for a in r["aircraft"]]
        self.db.add_audit(user["id"], "squawk", args.strip()[:6])
        lines = [f"🚨 <b>{tr(lang, 'رموز الطوارئ في الطيران', 'Aviation emergency squawks')}</b>"]
        lines.append("<blockquote>7700 " + tr(lang, "طوارئ عامة", "general emergency") + " · 7600 " + tr(lang, "عطل اتصالات", "radio failure") + " · 7500 " + tr(lang, "اختطاف", "hijack") + "</blockquote>")
        if found:
            lines.append("\n".join(f"{c} · " + aircraft_line(0, a, lang, show_pos=True) for c, a in found[:10]))
            lines.append("<i>" + tr(lang, "الرمز قد يُضبط خطأً أو لتدريب؛ لا تفترض حادثاً فعلياً.", "A code can be set by mistake or for training; do not assume a real incident.") + "</i>")
        else:
            lines.append("🟢 " + tr(lang, "لا طائرات تبثّ هذه الرموز الآن.", "No aircraft are squawking these codes right now."))
        self._send(chat_id, lines)

    # ================================================================== weather
    def cmd_metar(self, chat_id, user, args):
        lang = user["lang"]
        if not self._gate(chat_id, user, args, "🌦 /metar رمز_المطار ICAO — مثال: /metar DAAG (الجزائر) أو /metar LFPG", "🌦 /metar ICAO — e.g. /metar DAAG (Algiers) or /metar LFPG"):
            return
        with Typing(self.tg, chat_id):
            m = S.metar(args.strip().split()[0])
        if not m["ok"]:
            return self._fail(chat_id, user, "رمز غير صالح أو لا يوجد تقرير لهذا المطار.", "Invalid code or no report for this airport.")
        dot = {"VFR": "🟢", "MVFR": "🔵", "IFR": "🔴", "LIFR": "🟣"}.get(m["cat"], "⚪")
        wind = (f"{m['wdir']}° / {m['wspd']} kt" + (f" G{m['wgst']}" if m["wgst"] else "")) if m["wspd"] is not None else "—"
        q = [f"{dot} {tr(lang, 'فئة الطيران', 'Flight category')}: <b>{_e(m['cat'] or '?')}</b>", f"💨 {tr(lang, 'الرياح', 'Wind')}: {_e(wind)}",
             f"👁 {tr(lang, 'الرؤية', 'Visibility')}: {_e(m['visib'])} SM", f"🌡 {_e(m['temp'])}°C / {_e(m['dewp'])}°C", f"⏱ QNH: {_e(m['altim'])} hPa"]
        lines = [f"🌦 <b>METAR — {_e(m['icao'])}</b> {_e(m['name'])}", "<blockquote>" + "\n".join(q) + "</blockquote>", f"<code>{_e(m['raw'])}</code>"]
        if m["taf"]:
            lines.append(f"<b>TAF</b>\n<code>{_e(m['taf'])}</code>")
        lines.append("<i>" + tr(lang, "للاطلاع فقط؛ استخدم مصادر الأرصاد الرسمية للتخطيط الفعلي.", "For information only; use official meteorological sources for real flight planning.") + "</i>")
        self._send(chat_id, lines)

    def cmd_weather(self, chat_id, user, args):
        lang = user["lang"]
        if not self._gate(chat_id, user, args, "🌤 /weather مدينة — مثال: /weather الجزائر", "🌤 /weather city — e.g. /weather Algiers"):
            return
        place = self._place(chat_id, user, args)
        if not place:
            return
        with Typing(self.tg, chat_id):
            w = S.weather(place["lat"], place["lon"])
        if not w["ok"]:
            return self._fail(chat_id, user)
        c, d = w["current"], w["daily"]
        icon, ar, en = S.WMO.get(c.get("weather_code"), ("🌡", "—", "—"))
        q = [f"{icon} {tr(lang, ar, en)} · <b>{c.get('temperature_2m')}°C</b> ({tr(lang, 'يُحَسّ', 'feels')} {c.get('apparent_temperature')}°)",
             f"💧 {c.get('relative_humidity_2m')}% · ☁️ {c.get('cloud_cover')}% · 🌧 {c.get('precipitation')} mm",
             f"💨 {c.get('wind_speed_10m')} km/h {R.compass(c.get('wind_direction_10m') or 0)} ({tr(lang, 'هبّات', 'gusts')} {c.get('wind_gusts_10m')})",
             f"⏱ {round(c.get('pressure_msl') or 0)} hPa · 👁 {round((c.get('visibility') or 0) / 1000, 1)} km"]
        lines = [f"🌤 <b>{_e(place['name'])}</b>{(', ' + _e(place['country'])) if place['country'] else ''}", "<blockquote>" + "\n".join(q) + "</blockquote>"]
        days = []
        for i, day in enumerate((d.get("time") or [])[:3]):
            ic = S.WMO.get((d.get("weather_code") or [None] * 3)[i], ("🌡", "", ""))[0]
            days.append(f"{day[5:]}: {ic} {d['temperature_2m_min'][i]}° → {d['temperature_2m_max'][i]}° · 🌧 {d['precipitation_sum'][i]} mm")
        if days:
            lines.append("\n".join(days))
        lines.append("<i>Open-Meteo</i>")
        self._send(chat_id, lines)

    # ================================================================== space
    def cmd_iss(self, chat_id, user, args):
        lang = user["lang"]
        if not self._gate(chat_id, user, args, "", "", need_args=False):
            return
        with Typing(self.tg, chat_id):
            s = S.iss()
            place = S.geocode(args) if args.strip() else None
        if not s["ok"]:
            return self._fail(chat_id, user)
        q = [f"🌐 {s['lat']:.2f}°, {s['lon']:.2f}°", f"⬆️ {s['alt_km']:.0f} km · 🚀 {s['kmh']:.0f} km/h",
             f"👁 {_e(s['visibility'])}"]
        if place:
            q.append(f"📍 {tr(lang, 'المسافة إلى', 'Distance to')} {_e(place['name'])}: {R.haversine_km(place['lat'], place['lon'], s['lat'], s['lon']):.0f} km")
        lines = [f"🛰 <b>{tr(lang, 'المحطة الفضائية الدولية', 'International Space Station')}</b>", "<blockquote>" + "\n".join(q) + "</blockquote>",
                 "<i>wheretheiss.at · " + tr(lang, "تردد صوت/هواة 145.800 MHz عند المرور فوقك", "amateur voice/SSTV 145.800 MHz on a pass over you") + "</i>"]
        self._send(chat_id, lines, kb([[self._open_btn(chat_id, "🗺 " + tr(lang, "على الخريطة", "On the map"), portals.portal_url(s["lat"], s["lon"], "osm"))]]))

    def cmd_space(self, chat_id, user, args):
        lang = user["lang"]
        if not self._gate(chat_id, user, args, "", "", need_args=False):
            return
        with Typing(self.tg, chat_id):
            sw = S.space_weather()
        if not sw["ok"]:
            return self._fail(chat_id, user)
        sc = sw["scales"]
        q = [f"☀️ SFI: <b>{sw['sfi'] if sw['sfi'] is not None else '—'}</b>", f"🧲 Kp: <b>{sw['kp'] if sw['kp'] is not None else '—'}</b>"]
        if sc:
            q.append(f"NOAA R{sc.get('R', '-')} · S{sc.get('S', '-')} · G{sc.get('G', '-')}  ({tr(lang, 'انقطاع راديو · عاصفة إشعاعية · عاصفة مغناطيسية', 'radio blackout · radiation · geomagnetic')})")
        lines = [f"☀️ <b>{tr(lang, 'الطقس الفضائي وانتشار الموجات القصيرة', 'Space weather & HF propagation')}</b>", "<blockquote>" + "\n".join(q) + "</blockquote>"]
        lines += S.hf_outlook(sw["sfi"], sw["kp"], lang)
        lines.append("<i>NOAA SWPC · " + tr(lang, "قاعدة تقريبية وليست تنبؤاً", "rule of thumb, not a forecast") + "</i>")
        self._send(chat_id, lines)

    def cmd_quakes(self, chat_id, user, args):
        lang = user["lang"]
        if not self._gate(chat_id, user, args, "", "", need_args=False):
            return
        try:
            mag = float(args.strip().replace(",", ".")) if args.strip() else 4.5
        except ValueError:
            mag = 4.5
        mag = min(max(mag, 2.5), 8.0)
        with Typing(self.tg, chat_id):
            q = S.quakes(mag)
        if not q["ok"]:
            return self._fail(chat_id, user)
        lines = [f"🌋 <b>{tr(lang, 'الزلازل الأخيرة', 'Recent earthquakes')}</b> (M ≥ {mag:g})"]
        if q["items"]:
            lines.append("<blockquote>" + "\n".join(
                f"{'🔴' if x['mag'] >= 6 else '🟠' if x['mag'] >= 5 else '🟡'} <b>M{x['mag']:.1f}</b> · {_e(x['place'])} · {time.strftime('%m-%d %H:%M', time.gmtime(x['ts']))} UTC"
                + (f" · {x['depth']:.0f} km" if x['depth'] is not None else "") + (" 🌊" if x["tsunami"] else "") for x in q["items"]) + "</blockquote>")
        else:
            lines.append("🟢 " + tr(lang, "لا زلازل بهذه القوة في الفترة المعروضة.", "No earthquakes of that size in the period shown."))
        lines.append("<i>USGS</i>")
        self._send(chat_id, lines)

    # ================================================================== radio
    def cmd_radio(self, chat_id, user, args):
        lang = user["lang"]
        if not self._gate(chat_id, user, args, "📻 /radio اسم_إذاعة أو رمز_بلد — مثال: /radio DZ أو /radio quran", "📻 /radio name or country code — e.g. /radio DZ or /radio jazz"):
            return
        with Typing(self.tg, chat_id):
            r = S.radio_stations(args.strip())
        if not r["ok"]:
            return self._fail(chat_id, user)
        if not r["stations"]:
            return self.tg.send_message(chat_id, "🔍 " + tr(lang, "لا إذاعات مطابقة.", "No matching stations."))
        rows = [f'<a href="{_e(s["url"])}">{_e(s["name"] or "?")}</a> · {_e(s["country"])} · {_e(s["codec"])} {s["bitrate"] or ""}k' for s in r["stations"]]
        self._send(chat_id, [f"📻 <b>{tr(lang, 'محطات الإنترنت', 'Internet radio stations')}</b>", "<blockquote>" + "\n".join(rows) + "</blockquote>",
                             "<i>radio-browser.info · " + tr(lang, "روابط بث خارجية: افتحها في مشغّل صوت.", "external stream links: open them in a media player.") + "</i>"])

    # ================================================================== radio calculators (offline)
    def cmd_freq(self, chat_id, user, args):
        lang = user["lang"]
        if not args.strip():
            return self.tg.send_message(chat_id, tr(lang, "📡 /freq تردد — مثال: /freq 145.5 MHz أو /freq 7100 kHz أو /freq 1090", "📡 /freq frequency — e.g. /freq 145.5 MHz, /freq 7100 kHz or /freq 1090"))
        hz = R.parse_freq(args)
        if not hz:
            return self.tg.send_message(chat_id, "⚠️ " + tr(lang, "تردد غير صالح. أمثلة: 145.5 MHz · 7100 kHz · 2.4 GHz", "Invalid frequency. Examples: 145.5 MHz · 7100 kHz · 2.4 GHz"))
        info, w = R.lookup(hz), R.wavelength(hz)
        lines = [f"📡 <b>{R.fmt_freq(hz)}</b>"]
        body = [f"⭐ {_e(tr(lang, ar, en))}" for ar, en in info["special"]] + [f"📻 {_e(tr(lang, ar, en))}" for ar, en in info["bands"][:3]]
        lines.append("<blockquote>" + ("\n".join(body) if body else tr(lang, "خارج النطاقات المعروفة في الجدول.", "Outside the bands in my table.")) + "</blockquote>")
        lines.append(f"λ = {w['lambda_m']:.3f} m · λ/2 = {w['half']:.3f} m · λ/4 = {w['quarter']:.3f} m")
        lines.append("<i>" + tr(lang, "التوزيع حسب المنطقة 1 (ITU) وبشكل عام؛ تحقق من الجهة التنظيمية في بلدك قبل أي إرسال. الاستماع فقط لما هو مسموح قانوناً.",
                                  "ITU Region 1, general level; check your national regulator before transmitting. Listen only to what is legal in your country.") + "</i>")
        self._send(chat_id, lines)

    def cmd_wave(self, chat_id, user, args):
        lang = user["lang"]
        hz = R.parse_freq(args) if args.strip() else None
        if not hz:
            return self.tg.send_message(chat_id, tr(lang, "📏 /wave تردد — طول الموجة وأطوال الهوائيات. مثال: /wave 145.5 MHz", "📏 /wave frequency — wavelength and antenna lengths. e.g. /wave 145.5 MHz"))
        w = R.wavelength(hz)
        q = [f"λ = <b>{w['lambda_m']:.3f} m</b>", f"λ/2 = {w['half']:.3f} m", f"λ/4 = {w['quarter']:.3f} m",
             f"{tr(lang, 'ثنائي القطب نصف الموجة (تقريباً)', 'Half-wave dipole (approx.)')}: <b>{w['dipole_m']:.3f} m</b>",
             f"{tr(lang, 'هوائي رأسي ربع موجة', 'Quarter-wave vertical')}: <b>{w['vertical_m']:.3f} m</b>"]
        self._send(chat_id, [f"📏 <b>{R.fmt_freq(hz)}</b>", "<blockquote>" + "\n".join(q) + "</blockquote>",
                             "<i>" + tr(lang, "قاعدة 468/f للأسلاك؛ اضبط بجهاز SWR فعلياً.", "468/f rule for wire; tune with an SWR meter.") + "</i>"])

    def cmd_morse(self, chat_id, user, args):
        lang = user["lang"]
        if not args.strip():
            return self.tg.send_message(chat_id, tr(lang, "📶 /morse نص أو شيفرة مورس — يحوّل في الاتجاهين. مثال: /morse SOS", "📶 /morse text or Morse code — converts both ways. e.g. /morse SOS"))
        if R.looks_like_morse(args):
            out, title = R.from_morse(args.replace("·", ".").replace("–", "-").replace("−", "-")), "Morse → text"
        else:
            out, title = R.to_morse(args), "Text → Morse"
        if not out:
            return self.tg.send_message(chat_id, "⚠️ " + tr(lang, "لا أحرف مدعومة (A-Z و0-9 وعلامات شائعة).", "No supported characters (A-Z, 0-9, common punctuation)."))
        self._send(chat_id, [f"📶 <b>{title}</b>", f"<code>{_e(out[:1500])}</code>"])

    def cmd_phonetic(self, chat_id, user, args):
        if not args.strip():
            return self.tg.send_message(chat_id, tr(user["lang"], "🔤 /phonetic نص — الهجاء الصوتي NATO. مثال: /phonetic DZ73", "🔤 /phonetic text — NATO phonetic spelling. e.g. /phonetic DZ73"))
        out = R.phonetic(args)
        self._send(chat_id, ["🔤 <b>NATO</b>", f"<code>{_e(out or '—')}</code>"])

    def cmd_qcode(self, chat_id, user, args):
        lang = user["lang"]
        q = args.strip().upper()
        if q in R.QCODES:
            ar, en = R.QCODES[q]
            return self._send(chat_id, [f"📻 <b>{q}</b> — {_e(tr(lang, ar, en))}"])
        lines = [f"📻 <b>{tr(lang, 'رموز Q', 'Q-codes')}</b>", "<blockquote expandable>" + "\n".join(f"<b>{k}</b> — {_e(tr(lang, *v))}" for k, v in R.QCODES.items()) + "</blockquote>"]
        self._send(chat_id, lines)

    def cmd_grid(self, chat_id, user, args):
        lang = user["lang"]
        if not args.strip():
            return self.tg.send_message(chat_id, tr(lang, "🧭 /grid إحداثيات أو رمز Maidenhead — مثال: /grid 36.75,3.06 أو /grid JM16", "🧭 /grid coordinates or Maidenhead locator — e.g. /grid 36.75,3.06 or /grid JM16"))
        ll = R.parse_latlon(args)
        if ll:
            return self._send(chat_id, [f"🧭 <b>{ll[0]:.4f}, {ll[1]:.4f}</b>", f"Maidenhead: <code>{R.to_grid(*ll)}</code> (4: <code>{R.to_grid(*ll, pairs=2)}</code>)"])
        pos = R.from_grid(args.strip())
        if not pos:
            return self.tg.send_message(chat_id, "⚠️ " + tr(lang, "رمز غير صالح (مثال JM16 أو JM16ms).", "Invalid locator (e.g. JM16 or JM16ms)."))
        self._send(chat_id, [f"🧭 <b>{_e(args.strip().upper())}</b>", f"{pos[0]}, {pos[1]}"],
                   kb([[self._open_btn(chat_id, "🗺 " + tr(lang, "على الخريطة", "On the map"), portals.portal_url(pos[0], pos[1], "osm"))]]))

    def cmd_power(self, chat_id, user, args):
        lang = user["lang"]
        w = R.parse_power(args) if args.strip() else None
        if not w:
            return self.tg.send_message(chat_id, tr(lang, "🔌 /power قيمة — مثال: /power 30dBm أو /power 500mW أو /power 1W", "🔌 /power value — e.g. /power 30dBm, /power 500mW or /power 1W"))
        t = R.power_table(w)
        self._send(chat_id, ["🔌 <b>" + _e(args.strip()) + "</b>", f"<blockquote>{t['W']:.6g} W\n{t['mW']:.6g} mW\n{t['dBm']:.2f} dBm\n{t['dBW']:.2f} dBW</blockquote>"])

    def cmd_fspl(self, chat_id, user, args):
        lang = user["lang"]
        m = re.fullmatch(r"\s*(\S+(?:\s*[a-zA-Z]+)?)\s+([0-9]+(?:[.,][0-9]+)?)\s*(km|m)?\s*", args or "")
        hz = R.parse_freq(m.group(1)) if m else None
        if not (m and hz):
            return self.tg.send_message(chat_id, tr(lang, "📉 /fspl تردد مسافة — مثال: /fspl 145.5MHz 10km", "📉 /fspl frequency distance — e.g. /fspl 145.5MHz 10km"))
        d = float(m.group(2).replace(",", ".")) / (1000 if (m.group(3) or "km") == "m" else 1)
        if d <= 0:
            return self.tg.send_message(chat_id, "⚠️ " + tr(lang, "المسافة يجب أن تكون موجبة.", "Distance must be positive."))
        self._send(chat_id, [f"📉 <b>FSPL</b> — {R.fmt_freq(hz)} @ {d:g} km", f"<blockquote><b>{R.fspl_db(hz, d):.1f} dB</b></blockquote>",
                             "<i>" + tr(lang, "فقدان المسار في الفضاء الحر فقط؛ الواقع أسوأ (عوائق، أرض، أمطار).", "Free-space loss only; reality is worse (obstacles, ground, rain).") + "</i>"])

    def cmd_horizon(self, chat_id, user, args):
        lang = user["lang"]
        nums = re.findall(r"[0-9]+(?:[.,][0-9]+)?", args or "")
        if not nums:
            return self.tg.send_message(chat_id, tr(lang, "🗼 /horizon ارتفاع_الهوائي_م [ارتفاع_الطرف_الآخر_م] — مثال: /horizon 30 2", "🗼 /horizon antenna_height_m [other_end_m] — e.g. /horizon 30 2"))
        h1, h2 = float(nums[0].replace(",", ".")), float(nums[1].replace(",", ".")) if len(nums) > 1 else 0.0
        self._send(chat_id, [f"🗼 <b>{tr(lang, 'الأفق الراديوي', 'Radio horizon')}</b>", f"<blockquote>{h1:g} m ↔ {h2:g} m → <b>{R.radio_horizon_km(h1, h2):.1f} km</b></blockquote>",
                             "<i>" + tr(lang, "خط رؤية مع انكسار جوي قياسي (k=4/3).", "Line of sight with standard refraction (k = 4/3).") + "</i>"])

    def cmd_dist(self, chat_id, user, args):
        lang = user["lang"]
        parts = [p.strip() for p in re.split(r"\s*(?:->|→|;| to | الى | إلى )\s*", args or "") if p.strip()]
        if len(parts) != 2:
            return self.tg.send_message(chat_id, tr(lang, "📍 /dist مكان1 -> مكان2 — مثال: /dist Algiers -> Paris", "📍 /dist place1 -> place2 — e.g. /dist Algiers -> Paris"))
        a, b = S.geocode(parts[0]), S.geocode(parts[1])
        if not (a and b):
            return self.tg.send_message(chat_id, "🔍 " + tr(lang, "تعذّر تحديد أحد المكانين.", "Could not locate one of the places."))
        km = R.haversine_km(a["lat"], a["lon"], b["lat"], b["lon"])
        br = R.bearing_deg(a["lat"], a["lon"], b["lat"], b["lon"])
        self._send(chat_id, [f"📍 <b>{_e(a['name'])} → {_e(b['name'])}</b>",
                             f"<blockquote>{km:.0f} km ({km / 1.852:.0f} NM) · {br:.0f}° {R.compass(br)}\nMaidenhead: {R.to_grid(a['lat'], a['lon'])} → {R.to_grid(b['lat'], b['lon'])}</blockquote>"])

    # ================================================================== passive network intelligence
    def cmd_subdomains(self, chat_id, user, args):
        lang = user["lang"]
        if not self._gate(chat_id, user, args, "🧬 /subdomains نطاق — اكتشاف نطاقات فرعية من سجلات الشهادات (سلبي).", "🧬 /subdomains domain — passive subdomain discovery from certificate logs."):
            return
        d = netintel.valid_domain(args)
        if not d:
            return self._bad_domain(chat_id, user)
        with Typing(self.tg, chat_id):
            r = netintel.subdomains(d)
        self.db.add_audit(user["id"], "net_subdomains", d)
        if not r["ok"]:
            return self._fail(chat_id, user, "crt.sh مشغول أو غير متاح الآن.", "crt.sh is busy or unavailable right now.")
        lines = [f"🧬 <b>{tr(lang, 'نطاقات فرعية', 'Subdomains')} — {_e(d)}</b> ({r['count']})"]
        lines.append("<blockquote expandable>" + ("\n".join(_e(n) for n in r["names"][:80]) or "—") + (f"\n… +{r['count'] - 80}" if r["count"] > 80 else "") + "</blockquote>")
        lines.append("<i>" + tr(lang, "من سجلات شفافية الشهادات فقط؛ لا يُرسَل شيء إلى الهدف. استخدمه لأصولك أو بتفويض.", "From certificate-transparency logs only; nothing is sent to the target. Use it for your own assets or with authorisation.") + "</i>")
        self._send(chat_id, lines)

    def cmd_asn(self, chat_id, user, args):
        lang = user["lang"]
        if not self._gate(chat_id, user, args, "🛰 /asn عنوان_IP — الشبكة (ASN) والمالك وجهة الإبلاغ عن الإساءة.", "🛰 /asn IP — network (ASN), holder and abuse contact."):
            return
        with Typing(self.tg, chat_id):
            r = netintel.asn_info(args.strip().split()[0])
        if not r["ok"]:
            return self.tg.send_message(chat_id, "⚠️ " + tr(lang, "أدخل عنوان IP عاماً صحيحاً.", "Enter a valid public IP address.")) if r["error"] == "not_public_ip" else self._fail(chat_id, user)
        q = [f"AS<b>{r['asn']}</b> · {_e(r['holder'])}" if r["asn"] else tr(lang, "غير معلَن", "not announced"), f"{tr(lang, 'البادئة', 'Prefix')}: <code>{_e(r['prefix'])}</code>"]
        if r["abuse"]:
            q.append(f"📧 abuse: {_e(', '.join(r['abuse']))}")
        self.db.add_audit(user["id"], "net_asn", r["ip"])
        self._send(chat_id, [f"🛰 <b>ASN — {_e(r['ip'])}</b>", "<blockquote>" + "\n".join(q) + "</blockquote>", "<i>RIPEstat</i>"])

    def cmd_rdns(self, chat_id, user, args):
        lang = user["lang"]
        if not self._gate(chat_id, user, args, "🔁 /rdns عنوان_IP — اسم المضيف العكسي (PTR).", "🔁 /rdns IP — reverse DNS (PTR) name."):
            return
        with Typing(self.tg, chat_id):
            r = netintel.reverse_dns(args.strip().split()[0])
        if not r["ok"]:
            return self.tg.send_message(chat_id, "⚠️ " + tr(lang, "أدخل عنوان IP عاماً صحيحاً.", "Enter a valid public IP address."))
        self._send(chat_id, [f"🔁 <b>PTR — {_e(r['ip'])}</b>", "<blockquote>" + (_e("\n".join(r["names"])) or tr(lang, "لا سجل PTR", "no PTR record")) + "</blockquote>"])

    def cmd_mac(self, chat_id, user, args):
        lang = user["lang"]
        if not self._gate(chat_id, user, args, "🏷 /mac عنوان_MAC — الشركة المصنّعة (يُرسل أول 3 بايت فقط).", "🏷 /mac address — manufacturer (only the first 3 bytes are sent)."):
            return
        with Typing(self.tg, chat_id):
            r = netintel.mac_vendor(args.strip().split()[0])
        if r.get("error") == "invalid":
            return self.tg.send_message(chat_id, "⚠️ " + tr(lang, "عنوان MAC غير صالح.", "Invalid MAC address."))
        q = [f"OUI: <code>{r['oui']}</code>", f"{tr(lang, 'الشركة', 'Vendor')}: <b>{_e(r.get('vendor') or tr(lang, 'غير معروفة', 'unknown'))}</b>"]
        if r["random"]:
            q.append("🎲 " + tr(lang, "عنوان محلي/عشوائي (خصوصية الجهاز): لا يدل على مصنّع.", "Locally administered / randomised address: does not identify a maker."))
        self._send(chat_id, [f"🏷 <b>MAC</b>", "<blockquote>" + "\n".join(q) + "</blockquote>"])

    def cmd_exposure(self, chat_id, user, args):
        lang = user["lang"]
        if not self._gate(chat_id, user, args, "🔓 /exposure IP أو نطاق — ما يعرفه الإنترنت عن أصلك (منافذ، برمجيات، ثغرات). لأصولك أنت.",
                          "🔓 /exposure IP or domain — what the internet already knows about your asset (ports, software, CVEs). Your own assets only."):
            return
        with Typing(self.tg, chat_id):
            r = netintel.exposure(args.strip().split()[0])
        self.db.add_audit(user["id"], "net_exposure", args.strip()[:60])
        if not r["ok"]:
            return self.tg.send_message(chat_id, "⚠️ " + tr(lang, "أدخل عنواناً عاماً أو نطاقاً يُحلّ إلى عنوان عام.", "Enter a public address or a domain that resolves to one.")) if r["error"] == "not_public" else self._fail(chat_id, user)
        if not r["known"]:
            return self._send(chat_id, [f"🔓 <b>{_e(r['ip'])}</b>", "🟢 " + tr(lang, "لا بيانات معروفة لدى InternetDB (لا منافذ مكتشفة).", "Nothing known in InternetDB (no discovered ports).")])
        q = [f"{tr(lang, 'منافذ', 'Ports')}: <b>{_e(', '.join(map(str, r['ports'])) or '—')}</b>", f"{tr(lang, 'مضيفون', 'Hostnames')}: {_e(', '.join(r['hostnames']) or '—')}",
             f"CPE: {_e(', '.join(r['cpes'][:5]) or '—')}"]
        lines = [f"🔓 <b>{tr(lang, 'الانكشاف', 'Exposure')} — {_e(r['ip'])}</b>", "<blockquote>" + "\n".join(q) + "</blockquote>"]
        if r["vulns"]:
            lines.append(f"🔴 {tr(lang, 'ثغرات منسوبة', 'Associated CVEs')} ({len(r['vulns'])}): <code>{_e(', '.join(r['vulns'][:10]))}</code>\n"
                         + tr(lang, "أرسل أي CVE هنا للتحقق منه ومعرفة هل هو مستغَلّ فعلياً.", "Send any CVE id here to verify it and see whether it is actively exploited."))
        lines.append("<i>Shodan InternetDB · " + tr(lang, "سلبي: لم يُرسل أي شيء إلى الهدف.", "passive: nothing was sent to the target.") + "</i>")
        self._send(chat_id, lines)

    # ================================================================== menus
    def _world_rows(self, lang):
        return [
            [("✈️ " + tr(lang, "رادار الطائرات", "Aircraft radar"), "t:radar"), ("🛩 " + tr(lang, "رحلة", "Flight"), "t:flight"), ("🔎 " + tr(lang, "طائرة", "Plane"), "t:plane")],
            [("🚨 " + tr(lang, "طوارئ الطيران", "Emergency squawks"), "wd:squawk"), ("🌦 METAR", "t:metar")],
            [("🌤 " + tr(lang, "الطقس", "Weather"), "t:weather"), ("🌋 " + tr(lang, "الزلازل", "Earthquakes"), "wd:quakes")],
            [("🛰 ISS", "wd:iss"), ("☀️ " + tr(lang, "الطقس الفضائي / HF", "Space weather / HF"), "wd:space")],
            [("📻 " + tr(lang, "إذاعات الإنترنت", "Internet radio"), "t:radio"), ("📡 " + tr(lang, "ترددات", "Frequencies"), "t:freq")],
            [("🧰 " + tr(lang, "أدوات اللاسلكي", "Radio toolbox"), "m:rf"), ("🧭 " + tr(lang, "بوابات الويب", "Web portals"), "m:portals")],
        ]

    def show_world(self, chat_id, user, mid=None) -> None:
        lang = user["lang"]
        text = (f"🌍 <b>{tr(lang, 'العالم المباشر', 'Live world')}</b>\n<i>{tr(lang, 'رادار طيران، طقس، فضاء، راديو وبوابات ويب تُفتح داخل البوت.', 'Aircraft radar, weather, space, radio and web portals that open inside the bot.')}</i>")
        self._html_screen(chat_id, mid, text, kb(self._world_rows(lang) + [self.home_row(lang)]))

    def cmd_world(self, chat_id, user, args):
        self.show_world(chat_id, user)

    def show_rf(self, chat_id, user, mid=None) -> None:
        lang = user["lang"]
        rows = [[("📡 " + tr(lang, "ترددات", "Frequency"), "t:freq"), ("📏 " + tr(lang, "طول الموجة", "Wavelength"), "t:wave")],
                [("📶 " + tr(lang, "مورس", "Morse"), "t:morse"), ("🔤 " + tr(lang, "هجاء NATO", "NATO spelling"), "t:phonetic")],
                [("📻 " + tr(lang, "رموز Q", "Q-codes"), "wd:qcode"), ("🧭 Maidenhead", "t:grid")],
                [("🔌 dBm/W", "t:power"), ("📉 FSPL", "t:fspl")],
                [("🗼 " + tr(lang, "الأفق الراديوي", "Radio horizon"), "t:horizon"), ("📍 " + tr(lang, "مسافة واتجاه", "Distance & bearing"), "t:dist")],
                [("🔙 " + tr(lang, "العالم", "World"), "m:world")] + self.home_row(lang)]
        self._html_screen(chat_id, mid, f"🧰 <b>{tr(lang, 'أدوات اللاسلكي', 'Radio toolbox')}</b>\n<i>{tr(lang, 'حسابات محلية فورية بلا إنترنت.', 'Instant offline calculators.')}</i>", kb(rows))

    def cmd_rf(self, chat_id, user, args):
        self.show_rf(chat_id, user)

    def show_portals(self, chat_id, user, mid=None) -> None:
        lang = user["lang"]
        items = [(f"{ic} {ar if lang == 'ar' else en}", f"pt:{k}") for k, ic, ar, en, n in portals.categories()]
        rows = [items[i:i + 2] for i in range(0, len(items), 2)] + [[("🔙 " + tr(lang, "العالم", "World"), "m:world")] + self.home_row(lang)]
        text = (f"🧭 <b>{tr(lang, 'بوابات الويب المباشرة', 'Live web portals')}</b>\n<i>{tr(lang, 'اضغط لفتح الموقع داخل تيليجرام (في المحادثة الخاصة) — مواقع رسمية فقط.', 'Tap to open the site inside Telegram (private chats) — official sites only.')}</i>")
        self._html_screen(chat_id, mid, text, kb(rows))

    def cmd_portals(self, chat_id, user, args):
        self.show_portals(chat_id, user)

    def portals_callback(self, key: str, chat_id, user, mid) -> None:
        if key not in portals.PORTALS:
            return
        lang = user["lang"]
        icon, ar, en, items = portals.PORTALS[key]
        rows = [[self._open_btn(chat_id, f"{name} — {a if lang == 'ar' else n}"[:60], url)] for name, a, n, url in items]
        rows.append([("🔙 " + tr(lang, "البوابات", "Portals"), "m:portals")] + self.home_row(lang))
        self._html_screen(chat_id, mid, f"{icon} <b>{_e(ar if lang == 'ar' else en)}</b>", kb(rows))

    def world_direct(self, what: str, chat_id, user) -> None:
        """Buttons that need no input."""
        fn = {"iss": self.cmd_iss, "space": self.cmd_space, "quakes": self.cmd_quakes, "squawk": self.cmd_squawk, "qcode": self.cmd_qcode}.get(what)
        if fn:
            fn(chat_id, user, "")
