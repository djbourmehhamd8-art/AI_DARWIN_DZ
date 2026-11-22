"""Live public data for the bot's 'world' tools: aircraft (crowd-sourced ADS-B), aviation weather (METAR/TAF), weather,
the ISS, space weather for HF radio, earthquakes, internet radio stations and place search.
Every host is fixed (user text only ever goes into URL-encoded query strings or strictly validated path parts), results
are cached for a few seconds to respect free-tier limits, and every function returns plain dicts or lists — never raises."""
from __future__ import annotations

import math
import re
import threading
import time
import urllib.parse

import requests

from . import radiotools as R

UA = "DarwinBot/4.3 (Telegram security & radio assistant)"
_cache: dict = {}
_lock = threading.Lock()
_last_hit: dict = {}


def _get(url: str, params=None, http=requests, ttl: float = 20, timeout: float = 9, min_gap: float = 0.0, headers=None):
    """GET + JSON with a tiny cache and an optional minimum gap per host. Raises on HTTP errors (callers catch)."""
    key = url + "?" + urllib.parse.urlencode(sorted((params or {}).items()))
    now = time.monotonic()
    with _lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < ttl:
            return hit[1]
        if min_gap:
            host = urllib.parse.urlsplit(url).netloc
            wait = min_gap - (now - _last_hit.get(host, 0))
            if wait > 0:
                time.sleep(min(wait, min_gap))
            _last_hit[host] = time.monotonic()
    r = http.get(url, params=params, timeout=timeout, headers={"User-Agent": UA, "Accept": "application/json", **(headers or {})})
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code}")
    data = r.json()
    with _lock:
        if len(_cache) > 300:
            _cache.clear()
        _cache[key] = (time.monotonic(), data)
    return data


# ============================================================================================ places
def geocode(query: str, http=requests):
    """'Algiers', 'الجزائر العاصمة' or '36.75,3.06' -> {name, country, lat, lon} or None."""
    ll = R.parse_latlon(query)
    if ll:
        return {"name": f"{ll[0]:.4f}, {ll[1]:.4f}", "country": "", "lat": ll[0], "lon": ll[1]}
    q = " ".join((query or "").split())[:80]
    if len(q) < 2:
        return None
    lang = "ar" if re.search(r"[\u0600-\u06FF]", q) else "en"
    try:
        j = _get("https://geocoding-api.open-meteo.com/v1/search", {"name": q, "count": 1, "language": lang, "format": "json"}, http, ttl=3600)
        r = (j.get("results") or [None])[0]
    except Exception:                                                # noqa: BLE001
        return None
    return {"name": r.get("name", q), "country": r.get("country", ""), "lat": r["latitude"], "lon": r["longitude"]} if r else None


# ============================================================================================ aircraft (ADS-B)
AIRCRAFT_APIS = [("adsb.lol", "https://api.adsb.lol/v2"), ("airplanes.live", "https://api.airplanes.live/v2")]
EMERGENCY = {"7500": ("hijack", "اختطاف"), "7600": ("radio failure", "عطل اتصالات"), "7700": ("general emergency", "طوارئ عامة")}
_HEX = re.compile(r"^[0-9a-fA-F]{6}$")
_CALL = re.compile(r"^[A-Za-z0-9]{2,8}$")
_REG = re.compile(r"^[A-Za-z0-9-]{2,10}$")


def norm_aircraft(a: dict, center=None) -> dict:
    alt = a.get("alt_baro")
    on_ground = alt == "ground"
    alt_ft = 0 if on_ground else (int(alt) if isinstance(alt, (int, float)) else None)
    d = {"hex": str(a.get("hex", "")).lower(), "call": (a.get("flight") or "").strip(), "reg": a.get("r") or "", "type": a.get("t") or "",
         "alt_ft": alt_ft, "ground": on_ground, "gs": a.get("gs"), "track": a.get("track"), "lat": a.get("lat"), "lon": a.get("lon"),
         "squawk": str(a.get("squawk") or ""), "vs": a.get("baro_rate"), "dist_km": None, "bearing": None}
    if center and d["lat"] is not None and d["lon"] is not None:
        d["dist_km"] = R.haversine_km(center[0], center[1], d["lat"], d["lon"])
        d["bearing"] = R.bearing_deg(center[0], center[1], d["lat"], d["lon"])
    return d


def _aircraft_call(path: str, http, center=None, limit: int = 40):
    last = ""
    for name, base in AIRCRAFT_APIS:
        try:
            j = _get(base + path, None, http, ttl=8, min_gap=1.0)
            ac = [norm_aircraft(a, center) for a in (j.get("ac") or []) if isinstance(a, dict) and a.get("hex")]
            return {"ok": True, "provider": name, "aircraft": ac[:limit * 3]}
        except Exception as e:                                       # noqa: BLE001 - try the next feed
            last = f"{name}: {e}"
    return {"ok": False, "error": last or "no provider"}


def aircraft_near(lat: float, lon: float, radius_km: float = 50, http=requests) -> dict:
    nm = int(min(max(radius_km / 1.852, 1), 250))
    res = _aircraft_call(f"/point/{lat:.4f}/{lon:.4f}/{nm}", http, center=(lat, lon))
    if res["ok"]:
        res["aircraft"] = sorted((a for a in res["aircraft"] if a["dist_km"] is not None), key=lambda a: a["dist_km"])
        res["radius_km"] = nm * 1.852
    return res


def aircraft_lookup(kind: str, value: str, http=requests) -> dict:
    """kind: hex | callsign | reg | squawk — strictly validated before it enters the URL path."""
    v = (value or "").strip()
    ok = {"hex": bool(_HEX.match(v)), "callsign": bool(_CALL.match(v)), "reg": bool(_REG.match(v)), "squawk": bool(re.fullmatch(r"[0-7]{4}", v))}.get(kind, False)
    if not ok:
        return {"ok": False, "error": "invalid"}
    return _aircraft_call(f"/{kind}/{urllib.parse.quote(v.lower() if kind == 'hex' else v.upper(), safe='')}", http)


def radar_scope(aircraft: list, radius_km: float, cols: int = 31, rows: int = 15) -> str:
    """Text radar: centre '+', rings '·', aircraft 1-9 then A-Z by distance. North is up. Monospace."""
    grid = [[" "] * cols for _ in range(rows)]
    cx, cy = cols // 2, rows // 2
    sx, sy = (cols - 1) / 2, (rows - 1) / 2
    for frac in (1 / 3, 2 / 3, 1.0):
        for k in range(120):
            ang = k * 2 * math.pi / 120
            x = int(round(cx + sx * frac * math.sin(ang)))
            y = int(round(cy - sy * frac * math.cos(ang)))
            if 0 <= x < cols and 0 <= y < rows and grid[y][x] == " ":
                grid[y][x] = "·"
    grid[cy][cx] = "+"
    for i, a in enumerate(aircraft[:35]):
        if a.get("dist_km") is None or a["dist_km"] > radius_km:
            continue
        f = a["dist_km"] / radius_km
        x = int(round(cx + sx * f * math.sin(math.radians(a["bearing"]))))
        y = int(round(cy - sy * f * math.cos(math.radians(a["bearing"]))))
        if 0 <= x < cols and 0 <= y < rows:
            grid[y][x] = (str(i + 1) if i < 9 else chr(ord("A") + i - 9))
    top = "N".center(cols)
    return "\n".join([top] + ["".join(r).rstrip() for r in grid])


# ============================================================================================ aviation weather
def metar(icao: str, http=requests) -> dict:
    code = (icao or "").strip().upper()
    if not re.fullmatch(r"[A-Z]{4}", code):
        return {"ok": False, "error": "invalid"}
    try:
        j = _get("https://aviationweather.gov/api/data/metar", {"ids": code, "format": "json"}, http, ttl=60)
        m = (j or [None])[0]
        if not m:
            return {"ok": False, "error": "not_found"}
        taf = None
        try:
            t = _get("https://aviationweather.gov/api/data/taf", {"ids": code, "format": "json"}, http, ttl=300)
            taf = (t or [{}])[0].get("rawTAF")
        except Exception:                                            # noqa: BLE001 - TAF is optional
            pass
        return {"ok": True, "icao": code, "name": m.get("name", ""), "raw": m.get("rawOb", ""), "cat": m.get("fltCat", ""), "temp": m.get("temp"),
                "dewp": m.get("dewp"), "wdir": m.get("wdir"), "wspd": m.get("wspd"), "wgst": m.get("wgst"), "visib": m.get("visib"),
                "altim": m.get("altim"), "time": m.get("reportTime", ""), "taf": taf}
    except Exception as e:                                           # noqa: BLE001
        return {"ok": False, "error": str(e)}


WMO = {0: ("☀️", "صافٍ", "Clear"), 1: ("🌤", "غالباً صافٍ", "Mostly clear"), 2: ("⛅", "غائم جزئياً", "Partly cloudy"), 3: ("☁️", "غائم", "Overcast"),
       45: ("🌫", "ضباب", "Fog"), 48: ("🌫", "ضباب جليدي", "Rime fog"), 51: ("🌦", "رذاذ خفيف", "Light drizzle"), 53: ("🌦", "رذاذ", "Drizzle"),
       55: ("🌧", "رذاذ كثيف", "Heavy drizzle"), 61: ("🌧", "مطر خفيف", "Light rain"), 63: ("🌧", "مطر", "Rain"), 65: ("🌧", "مطر غزير", "Heavy rain"),
       66: ("🌧", "مطر متجمد", "Freezing rain"), 71: ("🌨", "ثلج خفيف", "Light snow"), 73: ("🌨", "ثلج", "Snow"), 75: ("❄️", "ثلج كثيف", "Heavy snow"),
       80: ("🌦", "زخات مطر", "Rain showers"), 81: ("🌧", "زخات قوية", "Heavy showers"), 82: ("⛈", "زخات عنيفة", "Violent showers"),
       95: ("⛈", "عاصفة رعدية", "Thunderstorm"), 96: ("⛈", "عاصفة مع برد", "Thunderstorm with hail"), 99: ("⛈", "عاصفة قوية مع برد", "Severe thunderstorm with hail")}


def weather(lat: float, lon: float, http=requests) -> dict:
    try:
        j = _get("https://api.open-meteo.com/v1/forecast", {
            "latitude": lat, "longitude": lon, "timezone": "auto", "forecast_days": 3, "wind_speed_unit": "kmh",
            "current": "temperature_2m,apparent_temperature,relative_humidity_2m,precipitation,weather_code,cloud_cover,pressure_msl,wind_speed_10m,wind_direction_10m,wind_gusts_10m,visibility",
            "daily": "weather_code,temperature_2m_max,temperature_2m_min,precipitation_sum"}, http, ttl=300)
        return {"ok": True, "current": j["current"], "daily": j.get("daily", {}), "tz": j.get("timezone", "")}
    except Exception as e:                                           # noqa: BLE001
        return {"ok": False, "error": str(e)}


# ============================================================================================ space
def iss(http=requests) -> dict:
    try:
        j = _get("https://api.wheretheiss.at/v1/satellites/25544", None, http, ttl=5)
        return {"ok": True, "lat": j["latitude"], "lon": j["longitude"], "alt_km": j["altitude"], "kmh": j["velocity"], "visibility": j.get("visibility", ""),
                "footprint_km": j.get("footprint")}
    except Exception as e:                                           # noqa: BLE001
        return {"ok": False, "error": str(e)}


def _last_kp(data):
    rows = data[1:] if data and isinstance(data[0], list) else data
    last = rows[-1] if rows else None
    if isinstance(last, list):
        return float(last[1]), last[0]
    if isinstance(last, dict):
        return float(last.get("Kp") or last.get("kp_index")), last.get("time_tag", "")
    return None, ""


def space_weather(http=requests) -> dict:
    out = {"ok": False, "kp": None, "sfi": None, "scales": {}}
    try:
        out["kp"], out["kp_time"] = _last_kp(_get("https://services.swpc.noaa.gov/products/noaa-planetary-k-index.json", None, http, ttl=300))
        out["ok"] = True
    except Exception as e:                                           # noqa: BLE001
        out["error"] = str(e)
    try:
        out["sfi"] = float(_get("https://services.swpc.noaa.gov/products/summary/10cm-flux.json", None, http, ttl=900).get("Flux"))
        out["ok"] = True
    except Exception:                                                # noqa: BLE001
        pass
    try:
        now = _get("https://services.swpc.noaa.gov/products/noaa-scales.json", None, http, ttl=300).get("0", {})
        out["scales"] = {k: (now.get(k) or {}).get("Scale") for k in ("R", "S", "G")}
    except Exception:                                                # noqa: BLE001
        pass
    return out


def hf_outlook(sfi, kp, lang: str) -> list:
    """Rough rule-of-thumb for HF propagation. NOT a forecast."""
    ar = lang == "ar"
    lines = []
    if sfi is not None:
        if sfi >= 150:
            lines.append("🟢 " + ("نشاط شمسي عالٍ: النطاقات العليا (15/12/10 م) غالباً مفتوحة نهاراً" if ar else "High solar flux: upper bands (15/12/10 m) likely open by day"))
        elif sfi >= 100:
            lines.append("🟡 " + ("نشاط متوسط: 20 و17 م جيدة، والعليا متقطعة" if ar else "Moderate flux: 20/17 m good, upper bands patchy"))
        else:
            lines.append("🟠 " + ("نشاط منخفض: الاعتماد على 40 و30 و20 م" if ar else "Low flux: rely on 40/30/20 m"))
    if kp is not None:
        if kp >= 5:
            lines.append("🔴 " + ("عاصفة مغناطيسية: تدهور واضح خصوصاً في المسارات القطبية" if ar else "Geomagnetic storm: marked degradation, especially on polar paths"))
        elif kp >= 4:
            lines.append("🟠 " + ("اضطراب مغناطيسي طفيف" if ar else "Unsettled geomagnetic field"))
        else:
            lines.append("🟢 " + ("مجال مغناطيسي هادئ" if ar else "Quiet geomagnetic field"))
    return lines


# ============================================================================================ earthquakes
def quakes(min_mag: float = 4.5, http=requests) -> dict:
    feed = "significant_week" if min_mag >= 6 else "4.5_day" if min_mag >= 4.5 else "2.5_day"
    try:
        j = _get(f"https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/{feed}.geojson", None, http, ttl=120)
        items = []
        for f in j.get("features", []):
            p, g = f.get("properties", {}), (f.get("geometry") or {}).get("coordinates", [None, None, None])
            if p.get("mag") is not None and p["mag"] >= min_mag:
                items.append({"mag": p["mag"], "place": p.get("place", ""), "ts": (p.get("time") or 0) / 1000, "url": p.get("url", ""),
                              "depth": g[2] if len(g) > 2 else None, "tsunami": bool(p.get("tsunami")), "lat": g[1], "lon": g[0]})
        items.sort(key=lambda x: -x["ts"])
        return {"ok": True, "feed": feed, "items": items[:10], "total": len(items)}
    except Exception as e:                                           # noqa: BLE001
        return {"ok": False, "error": str(e)}


# ============================================================================================ internet radio
RADIO_HOSTS = ["https://de1.api.radio-browser.info", "https://nl1.api.radio-browser.info", "https://at1.api.radio-browser.info"]


def radio_stations(query: str, http=requests, limit: int = 8) -> dict:
    q = (query or "").strip()
    params = {"limit": limit, "hidebroken": "true", "order": "clickcount", "reverse": "true"}
    if re.fullmatch(r"[A-Za-z]{2}", q):
        path, params["countrycode"] = "/json/stations/search", q.upper()
    else:
        path, params["name"] = "/json/stations/search", q[:60]
    last = ""
    for host in RADIO_HOSTS:
        try:
            rows = _get(host + path, params, http, ttl=300)
            return {"ok": True, "stations": [{"name": (s.get("name") or "").strip()[:60], "url": s.get("url_resolved") or s.get("url") or "",
                                              "country": s.get("country", ""), "codec": s.get("codec", ""), "bitrate": s.get("bitrate"),
                                              "tags": (s.get("tags") or "")[:50], "home": s.get("homepage", "")}
                                             for s in rows if str(s.get("url_resolved") or s.get("url") or "").startswith(("http://", "https://"))][:limit]}
        except Exception as e:                                       # noqa: BLE001
            last = str(e)
    return {"ok": False, "error": last}
