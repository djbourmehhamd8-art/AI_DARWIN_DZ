"""Live web portals that can be opened from inside the bot (buttons open in Telegram's built-in browser in private chats).
Official/well-known sites only."""
from __future__ import annotations

# key -> (icon, Arabic title, English title, [(name, Arabic note, English note, url)])
PORTALS = {
    "air": ("✈️", "الطيران والرادار", "Aviation & radar", [
        ("ADS-B Exchange", "خريطة طائرات مفتوحة وغير مفلترة", "Open, unfiltered aircraft map", "https://globe.adsbexchange.com"),
        ("airplanes.live", "خريطة ADS-B مجتمعية", "Community ADS-B map", "https://globe.airplanes.live"),
        ("Flightradar24", "تتبع الرحلات الأشهر", "The best-known flight tracker", "https://www.flightradar24.com"),
        ("FlightAware", "تتبع الرحلات والمطارات", "Flight and airport tracking", "https://www.flightaware.com/live/"),
        ("Plane Finder", "خريطة طائرات مباشرة", "Live aircraft map", "https://planefinder.net"),
        ("LiveATC", "اتصالات برج المراقبة الحية", "Live air-traffic-control audio", "https://www.liveatc.net"),
        ("SKYbrary", "موسوعة سلامة الطيران", "Aviation safety encyclopedia", "https://skybrary.aero"),
    ]),
    "sea": ("🚢", "البحر والسفن", "Sea & ships", [
        ("MarineTraffic", "تتبع السفن AIS", "AIS ship tracking", "https://www.marinetraffic.com"),
        ("VesselFinder", "تتبع السفن والموانئ", "Vessels and ports", "https://www.vesselfinder.com"),
        ("Global Fishing Watch", "نشاط الصيد في العالم", "Global fishing activity", "https://globalfishingwatch.org/map/"),
    ]),
    "space": ("🛰", "الفضاء والأقمار", "Space & satellites", [
        ("N2YO", "تتبع الأقمار ومواعيد المرور", "Satellite tracking and passes", "https://www.n2yo.com"),
        ("Heavens-Above", "مواعيد رؤية ISS والأقمار", "ISS and satellite visibility times", "https://www.heavens-above.com"),
        ("CelesTrak", "بيانات مدارات الأقمار TLE", "Satellite orbit data (TLE)", "https://celestrak.org"),
        ("Stellarium Web", "خريطة السماء المباشرة", "Live sky map", "https://stellarium-web.org"),
        ("NASA Eyes", "مجسّم تفاعلي للمجموعة الشمسية", "Interactive solar system", "https://eyes.nasa.gov"),
        ("NOAA Space Weather", "الطقس الفضائي", "Space weather", "https://www.swpc.noaa.gov"),
    ]),
    "radio": ("📻", "الراديو والاستقبال", "Radio & receivers", [
        ("Radio Garden", "استمع لإذاعات العالم على الكرة الأرضية", "Listen to the world's stations on a globe", "https://radio.garden"),
        ("WebSDR", "أجهزة استقبال SDR عبر الويب", "Web-based SDR receivers", "https://websdr.org"),
        ("KiwiSDR", "شبكة مستقبلات موجات قصيرة عالمية", "Worldwide shortwave receiver network", "https://kiwisdr.com/public/"),
        ("RadioReference", "قواعد بيانات ترددات الاتصالات", "Frequency databases", "https://www.radioreference.com"),
        ("Broadcastify", "بث اتصالات لاسلكية عامة", "Public safety radio streams", "https://www.broadcastify.com"),
        ("DX Cluster / HamQTH", "أدوات هواة اللاسلكي", "Amateur radio tools", "https://www.hamqth.com"),
        ("VOACAP Online", "توقع انتشار الموجات القصيرة", "HF propagation prediction", "https://www.voacap.com"),
    ]),
    "earth": ("🌍", "الطقس والأرض", "Weather & Earth", [
        ("Windy", "خرائط الرياح والطقس", "Wind and weather maps", "https://www.windy.com"),
        ("Zoom Earth", "صور الأقمار والأعاصير", "Satellite imagery and storms", "https://zoom.earth"),
        ("earth.nullschool", "حركة الرياح والمحيطات", "Global wind and ocean flow", "https://earth.nullschool.net"),
        ("USGS Earthquakes", "خريطة الزلازل", "Earthquake map", "https://earthquake.usgs.gov/earthquakes/map/"),
        ("NASA FIRMS", "الحرائق النشطة", "Active fires", "https://firms.modaps.eosdis.nasa.gov/map/"),
        ("OpenStreetMap", "خريطة مفتوحة", "Open map", "https://www.openstreetmap.org"),
    ]),
    "cyber": ("🛡", "الأمن السيبراني المباشر", "Live cybersecurity", [
        ("Kaspersky Cybermap", "هجمات سيبرانية مباشرة", "Live cyber-attack map", "https://cybermap.kaspersky.com"),
        ("Check Point Threat Map", "خريطة التهديدات الحية", "Live threat map", "https://threatmap.checkpoint.com"),
        ("Cloudflare Radar", "اتجاهات الإنترنت والهجمات", "Internet trends and attacks", "https://radar.cloudflare.com"),
        ("Downdetector", "انقطاع الخدمات", "Service outages", "https://downdetector.com"),
        ("urlscan.io", "فحص روابط في بيئة معزولة", "Sandboxed URL scanning", "https://urlscan.io"),
        ("VirusTotal", "فحص ملفات وروابط", "Files and URLs", "https://www.virustotal.com"),
        ("GreyNoise Visualizer", "ضجيج الإنترنت والماسحات", "Internet background noise and scanners", "https://viz.greynoise.io"),
        ("Shodan", "محرك الأجهزة المتصلة", "Internet-connected device search", "https://www.shodan.io"),
        ("MITRE ATT&CK", "تقنيات المهاجمين", "Adversary techniques", "https://attack.mitre.org"),
        ("CISA KEV", "ثغرات مستغَلّة", "Known exploited vulnerabilities", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
    ]),
}


def categories() -> list:
    return [(k, v[0], v[1], v[2], len(v[3])) for k, v in PORTALS.items()]


def portal_url(lat=None, lon=None, kind: str = "adsb") -> str:
    """Deep links centred on coordinates (used by /radar and /iss)."""
    if lat is None or lon is None:
        return "https://globe.adsbexchange.com"
    if kind == "osm":
        return f"https://www.openstreetmap.org/?mlat={lat:.4f}&mlon={lon:.4f}#map=5/{lat:.4f}/{lon:.4f}"
    return f"https://globe.adsbexchange.com/?lat={lat:.4f}&lon={lon:.4f}&zoom=8"
