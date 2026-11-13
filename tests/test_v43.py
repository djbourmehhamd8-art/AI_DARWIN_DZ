"""v4.3: live world tools (aircraft radar, METAR, weather, ISS, space weather, quakes, radio), radio calculators,
passive network intelligence, web portals and Mini-App buttons."""
import math
import unittest
from unittest import mock

from bot import netintel as N
from bot import portals
from bot import radiotools as R
from bot import skytools as S
from bot.telegram import TelegramAPI
from bot.ui import kb
from tests import test_integration as ti
from tests.test_ui import cb, message
from tests.test_v34 import Harness


class Resp:
    def __init__(self, js=None, status=200, text=""):
        self._js, self.status_code, self.text = js, status, text

    def json(self):
        return self._js


class Http:
    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def get(self, url, params=None, **kw):
        self.calls.append((url, params, kw))
        for k, v in self.routes.items():
            if k in url:
                if isinstance(v, Exception):
                    raise v
                return v(url, params) if callable(v) else v
        raise AssertionError("unexpected " + url)


class RadioMaths(unittest.TestCase):
    def test_frequency_parsing_and_lookup(self):
        self.assertEqual(R.parse_freq("145.5 MHz"), 145.5e6)
        self.assertEqual(R.parse_freq("7100kHz"), 7.1e6)
        self.assertEqual(R.parse_freq("1090"), 1090e6)
        self.assertEqual(R.parse_freq("2,4ghz"), 2.4e9)
        for bad in ("", "abc", "5 xyz", "-3", "1e99"):
            self.assertIsNone(R.parse_freq(bad), bad)
        self.assertTrue(R.lookup(121.5e6)["special"])
        self.assertTrue(R.lookup(156.8e6)["special"])
        self.assertTrue(any("ADS-B" in en for _, en in R.lookup(1090e6)["special"]))
        self.assertEqual(R.lookup(145.5e6)["bands"][0][1], "Amateur 2 m")
        self.assertEqual(R.lookup(100e6)["bands"][0][1], "FM broadcast")
        self.assertEqual(R.lookup(2.4e9)["bands"][0][1], "Wi-Fi / Bluetooth / ZigBee 2.4 GHz")

    def test_wavelength_and_antennas(self):
        w = R.wavelength(145e6)
        self.assertAlmostEqual(w["lambda_m"], 2.0675, places=3)
        self.assertAlmostEqual(w["quarter"], w["lambda_m"] / 4)
        self.assertAlmostEqual(w["dipole_m"], 468 / 145 * 0.3048, places=3)

    def test_morse_both_ways(self):
        self.assertEqual(R.to_morse("SOS"), "... --- ...")
        self.assertEqual(R.from_morse("... --- ... / -.-. --.-"), "SOS CQ")
        self.assertEqual(R.from_morse(R.to_morse("DZ 73 de dz")), "DZ 73 DE DZ")
        self.assertTrue(R.looks_like_morse("... --- ..."))
        self.assertFalse(R.looks_like_morse("hello"))
        self.assertFalse(R.looks_like_morse(""))

    def test_phonetic_and_qcodes(self):
        self.assertEqual(R.phonetic("dz7"), "Delta · Zulu · Seven")
        self.assertEqual(R.phonetic("9"), "Niner")
        for code in ("QTH", "QSL", "QRZ", "QNH", "QSY"):
            self.assertIn(code, R.QCODES)

    def test_maidenhead_roundtrip(self):
        g = R.to_grid(36.75, 3.06)
        self.assertEqual(g[:4], "JM16")
        lat, lon = R.from_grid(g)
        self.assertLess(abs(lat - 36.75), 0.05)
        self.assertLess(abs(lon - 3.06), 0.1)
        self.assertEqual(R.to_grid(51.5, -0.12), "IO91wm")
        self.assertIsNone(R.from_grid("ZZ99"))
        self.assertIsNone(R.from_grid("hello"))

    def test_power_units(self):
        self.assertAlmostEqual(R.parse_power("30dBm"), 1.0)
        self.assertAlmostEqual(R.parse_power("500mW"), 0.5)
        self.assertAlmostEqual(R.parse_power("0 dBW"), 1.0)
        t = R.power_table(1.0)
        self.assertEqual((round(t["dBm"], 6), t["mW"]), (30.0, 1000.0))
        self.assertIsNone(R.parse_power("abc"))
        self.assertIsNone(R.parse_power("0W"))

    def test_link_budget_and_horizon(self):
        self.assertAlmostEqual(R.fspl_db(145e6, 10), 95.67, places=1)
        self.assertAlmostEqual(R.fspl_db(2.4e9, 1), 100.05, places=1)
        self.assertAlmostEqual(R.radio_horizon_km(100, 0), 41.2, places=1)

    def test_geometry(self):
        self.assertAlmostEqual(R.haversine_km(36.75, 3.06, 48.85, 2.35), 1347, delta=6)
        self.assertAlmostEqual(R.bearing_deg(0, 0, 0, 10), 90, delta=0.01)
        self.assertEqual(R.compass(0), "N")
        self.assertEqual(R.compass(359), "N")
        self.assertEqual(R.compass(95), "E")
        self.assertEqual(R.parse_latlon("36.75, 3.06"), (36.75, 3.06))
        self.assertIsNone(R.parse_latlon("91,0"))
        self.assertIsNone(R.parse_latlon("a,b"))


AC = {"ac": [{"hex": "0A1B2C", "flight": "DAH1001 ", "r": "7T-VJA", "t": "A332", "alt_baro": 35000, "gs": 450.2, "track": 45, "lat": 37.0, "lon": 3.5, "squawk": "7700"},
             {"hex": "ffffff", "alt_baro": "ground", "lat": 36.7, "lon": 3.2, "squawk": "1200"},
             {"hex": "nopos"}, "junk"]}


class Aircraft(unittest.TestCase):
    def setUp(self):
        S._cache.clear()

    def test_normalise_and_sort(self):
        r = S.aircraft_near(36.75, 3.06, 100, Http({"adsb.lol": Resp(AC)}))
        self.assertEqual((r["ok"], r["provider"]), (True, "adsb.lol"))
        a = r["aircraft"]
        self.assertEqual([x["call"] for x in a], ["", "DAH1001"])                    # ground aircraft first (nearer), no-position dropped
        self.assertTrue(a[0]["ground"])
        self.assertEqual(a[1]["alt_ft"], 35000)
        self.assertEqual(a[1]["hex"], "0a1b2c")
        self.assertIn(a[1]["squawk"], S.EMERGENCY)

    def test_radius_is_capped_and_second_feed_is_used(self):
        http = Http({"adsb.lol": ConnectionError("down"), "airplanes.live": Resp(AC)})
        r = S.aircraft_near(36.75, 3.06, 5000, http)
        self.assertEqual(r["provider"], "airplanes.live")
        self.assertTrue(http.calls[0][0].endswith("/250"))                            # 250 NM maximum

    def test_all_feeds_down(self):
        r = S.aircraft_near(1, 1, 50, Http({"adsb.lol": ConnectionError("a"), "airplanes.live": Resp(status=503)}))
        self.assertFalse(r["ok"])

    def test_lookup_values_are_validated_before_entering_the_url(self):
        http = Http({"": Resp(AC)})
        for kind, bad in (("callsign", "../etc/passwd"), ("callsign", "AB CD"), ("hex", "12345"), ("hex", "zzzzzz"), ("reg", "a/b"),
                          ("squawk", "7777x"), ("squawk", "8888"), ("evil", "ABC123")):
            self.assertEqual(S.aircraft_lookup(kind, bad, http), {"ok": False, "error": "invalid"}, (kind, bad))
        self.assertEqual(http.calls, [])
        self.assertTrue(S.aircraft_lookup("callsign", "dah1001", http)["ok"])
        self.assertTrue(http.calls[0][0].endswith("/callsign/DAH1001"))

    def test_radar_scope_shape(self):
        r = S.aircraft_near(36.75, 3.06, 100, Http({"adsb.lol": Resp(AC)}))
        scope = S.radar_scope(r["aircraft"], r["radius_km"])
        self.assertIn("+", scope)
        self.assertIn("1", scope)
        self.assertTrue(scope.startswith(" ") and "N" in scope.split("\n")[0])
        self.assertLessEqual(max(len(x) for x in scope.split("\n")), 31)
        self.assertEqual(S.radar_scope([], 50).count("1"), 0)


class Weather(unittest.TestCase):
    def setUp(self):
        S._cache.clear()

    def test_metar_and_taf(self):
        http = Http({"metar": Resp([{"icaoId": "DAAG", "name": "Algiers", "rawOb": "DAAG 1200Z 27010KT 9999 FEW030 22/12 Q1015", "fltCat": "VFR", "temp": 22, "dewp": 12,
                                     "wdir": 270, "wspd": 10, "visib": "6+", "altim": 1015}]), "taf": Resp([{"rawTAF": "TAF DAAG ..."}])})
        m = S.metar("daag", http)
        self.assertEqual((m["ok"], m["cat"], m["wspd"], m["taf"]), (True, "VFR", 10, "TAF DAAG ..."))

    def test_metar_validation_and_missing(self):
        self.assertEqual(S.metar("x", Http({})), {"ok": False, "error": "invalid"})
        self.assertEqual(S.metar("ABC1", Http({})), {"ok": False, "error": "invalid"})
        self.assertEqual(S.metar("ZZZZ", Http({"metar": Resp([])}))["error"], "not_found")

    def test_weather(self):
        j = {"timezone": "Africa/Algiers", "current": {"temperature_2m": 21.5, "weather_code": 1}, "daily": {"time": ["2026-11-10"], "temperature_2m_max": [24], "temperature_2m_min": [15],
                                                                                                           "precipitation_sum": [0], "weather_code": [1]}}
        w = S.weather(36.75, 3.06, Http({"open-meteo": Resp(j)}))
        self.assertEqual((w["ok"], w["current"]["temperature_2m"]), (True, 21.5))
        self.assertFalse(S.weather(1, 1, Http({"open-meteo": ConnectionError("x")}))["ok"])
        for code in (0, 3, 45, 63, 95):
            self.assertIn(code, S.WMO)

    def test_geocode(self):
        http = Http({"geocoding": Resp({"results": [{"name": "Algiers", "country": "Algeria", "latitude": 36.7, "longitude": 3.0}]})})
        self.assertEqual(S.geocode("Algiers", http)["country"], "Algeria")
        self.assertEqual(S.geocode("36.75,3.06", Http({}))["lat"], 36.75)                 # coordinates never hit the network
        self.assertIsNone(S.geocode("x", Http({})))
        self.assertIsNone(S.geocode("nowhere", Http({"geocoding": Resp({})})))
        self.assertIsNone(S.geocode("nowhere", Http({"geocoding": ConnectionError("x")})))
        ar = Http({"geocoding": Resp({"results": []})})
        S.geocode("الجزائر العاصمة", ar)
        self.assertEqual(ar.calls[0][1]["language"], "ar")


class Space(unittest.TestCase):
    def setUp(self):
        S._cache.clear()

    def test_iss(self):
        r = S.iss(Http({"wheretheiss": Resp({"latitude": 12.3, "longitude": 45.6, "altitude": 420.1, "velocity": 27600, "visibility": "daylight"})}))
        self.assertEqual((r["ok"], round(r["alt_km"])), (True, 420))

    def test_space_weather_both_kp_formats(self):
        old = [["time_tag", "Kp", "a", "n"], ["2026-11-09 00:00:00", "2.33", "9", "8"], ["2026-11-09 03:00:00", "5.67", "30", "8"]]
        new = [{"time_tag": "2026-11-09T03:00:00", "Kp": 3.0}]
        for kp_data, kp in ((old, 5.67), (new, 3.0)):
            S._cache.clear()
            r = S.space_weather(Http({"planetary-k-index": Resp(kp_data), "10cm-flux": Resp({"Flux": "152"}),
                                      "noaa-scales": Resp({"0": {"R": {"Scale": "1"}, "S": {"Scale": "0"}, "G": {"Scale": "2"}}})}))
            self.assertEqual((r["ok"], r["kp"], r["sfi"], r["scales"]["G"]), (True, kp, 152.0, "2"))

    def test_space_weather_partial_failure(self):
        r = S.space_weather(Http({"planetary-k-index": ConnectionError("x"), "10cm-flux": Resp({"Flux": "90"}), "noaa-scales": ConnectionError("y")}))
        self.assertEqual((r["ok"], r["kp"], r["sfi"]), (True, None, 90.0))

    def test_hf_outlook(self):
        self.assertTrue(any("🟢" in x for x in S.hf_outlook(160, 1, "en")))
        self.assertTrue(any("🔴" in x for x in S.hf_outlook(160, 6, "en")))
        self.assertTrue(any("🟠" in x for x in S.hf_outlook(70, 1, "ar")))
        self.assertEqual(S.hf_outlook(None, None, "en"), [])

    def test_quakes(self):
        feats = [{"properties": {"mag": 5.2, "place": "A", "time": 2000000, "url": "u", "tsunami": 0}, "geometry": {"coordinates": [1, 2, 10]}},
                 {"properties": {"mag": 4.6, "place": "B", "time": 3000000, "tsunami": 1}, "geometry": {"coordinates": [1, 2, 33]}},
                 {"properties": {"mag": None, "place": "C", "time": 1}, "geometry": {"coordinates": [1, 2, 3]}}]
        r = S.quakes(4.5, Http({"usgs.gov": Resp({"features": feats})}))
        self.assertEqual([x["place"] for x in r["items"]], ["B", "A"])
        self.assertTrue(r["items"][0]["tsunami"])
        self.assertEqual(S.quakes(6.5, Http({"significant_week": Resp({"features": feats})}))["items"], [])

    def test_radio_stations(self):
        rows = [{"name": " Chaine 3 ", "url_resolved": "https://x/stream", "country": "Algeria", "codec": "MP3", "bitrate": 128},
                {"name": "bad", "url_resolved": "javascript:alert(1)"}, {"name": "no url"}]
        http = Http({"de1.api": ConnectionError("down"), "nl1.api": Resp(rows)})
        r = S.radio_stations("DZ", http)
        self.assertEqual([s["name"] for s in r["stations"]], ["Chaine 3"])
        self.assertEqual(http.calls[1][1]["countrycode"], "DZ")
        self.assertEqual(S.radio_stations("quran", Http({"de1.api": Resp([])}))["stations"], [])
        self.assertFalse(S.radio_stations("x", Http({"api": ConnectionError("z")}))["ok"])

    def test_cache_prevents_repeat_calls(self):
        http = Http({"wheretheiss": Resp({"latitude": 1, "longitude": 2, "altitude": 3, "velocity": 4})})
        S.iss(http)
        S.iss(http)
        self.assertEqual(len(http.calls), 1)


class PassiveIntel(unittest.TestCase):
    def test_public_ip_rules(self):
        self.assertEqual(N.public_ip("8.8.8.8"), "8.8.8.8")
        self.assertEqual(N.public_ip("[2606:4700::1111]"), "2606:4700::1111")
        for bad in ("10.0.0.1", "127.0.0.1", "169.254.169.254", "192.168.1.1", "172.16.0.9", "100.64.0.1", "::1", "x", "", "0.0.0.0", "224.0.0.1"):
            self.assertIsNone(N.public_ip(bad), bad)

    def test_subdomains_from_ct_logs(self):
        rows = [{"name_value": "a.example.com\n*.b.example.com"}, {"name_value": "example.com"}, {"name_value": "evil.com\nx.notexample.com"}, {"name_value": "A.EXAMPLE.COM"}]
        r = N.subdomains("example.com", Http({"crt.sh": Resp(rows)}))
        self.assertEqual(r["names"], ["a.example.com", "b.example.com"])
        self.assertFalse(N.subdomains("example.com", Http({"crt.sh": Resp(status=503)}))["ok"])
        self.assertFalse(N.subdomains("example.com", Http({"crt.sh": ConnectionError("x")}))["ok"])

    def test_asn(self):
        http = Http({"prefix-overview": Resp({"data": {"resource": "8.8.8.0/24", "announced": True, "asns": [{"asn": 15169, "holder": "GOOGLE"}]}}),
                     "abuse-contact": Resp({"data": {"abuse_contacts": ["abuse@google.com"]}})})
        r = N.asn_info("8.8.8.8", http)
        self.assertEqual((r["asn"], r["holder"], r["abuse"]), (15169, "GOOGLE", ["abuse@google.com"]))
        quiet = Http({})
        self.assertEqual(N.asn_info("10.1.1.1", quiet), {"ok": False, "error": "not_public_ip"})
        self.assertEqual(quiet.calls, [])

    def test_reverse_dns(self):
        http = Http({"cloudflare-dns": Resp({"Answer": [{"type": 12, "data": "dns.google."}]})})
        self.assertEqual(N.reverse_dns("8.8.8.8", http)["names"], ["dns.google"])
        self.assertEqual(http.calls[0][1]["name"], "8.8.8.8.in-addr.arpa")
        self.assertFalse(N.reverse_dns("192.168.0.1", Http({}))["ok"])

    def test_mac_vendor_sends_only_the_oui(self):
        http = Http({"macvendors": Resp(text="Cisco Systems")})
        r = N.mac_vendor("00:1A:2B:3C:4D:5E", http)
        self.assertEqual((r["oui"], r["vendor"], r["random"]), ("001A2B", "Cisco Systems", False))
        self.assertTrue(http.calls[0][0].endswith("/001A2B"))
        self.assertTrue(N.mac_vendor("02:00:00:00:00:01", Http({"macvendors": Resp(status=404)}))["random"])
        for bad in ("zz", "12", "00:1A:2B:3C:4D:5E:6F:70", "../../x"):
            self.assertEqual(N.mac_vendor(bad, Http({}))["error"], "invalid", bad)

    def test_exposure(self):
        j = {"ports": [443, 22], "hostnames": ["h.example"], "cpes": ["cpe:/a:openbsd:openssh:7.4"], "vulns": ["CVE-2018-15473"], "tags": []}
        r = N.exposure("93.184.216.34", Http({"internetdb": Resp(j)}))
        self.assertEqual((r["ports"], r["vulns"], r["known"]), ([22, 443], ["CVE-2018-15473"], True))
        self.assertFalse(N.exposure("93.184.216.34", Http({"internetdb": Resp(status=404)}))["known"])
        quiet = Http({})
        self.assertEqual(N.exposure("10.0.0.5", quiet)["error"], "not_public")
        self.assertEqual(N.exposure("localhost", quiet)["error"], "not_public")
        self.assertEqual(quiet.calls, [])
        d = N.exposure("example.com", Http({"internetdb": Resp(j)}), resolve_a=lambda dom: ["10.0.0.1", "93.184.216.34"])
        self.assertEqual(d["ip"], "93.184.216.34")                                       # a private answer is skipped
        self.assertEqual(N.exposure("example.com", Http({}), resolve_a=lambda dom: ["127.0.0.1"])["error"], "not_public")


class FetchGuardHardening(unittest.TestCase):
    def test_multicast_is_never_a_valid_fetch_target(self):
        from bot import websearch as W
        fake = [(2, 1, 6, "", ("224.0.0.251", 0))]
        with mock.patch("bot.websearch.socket.getaddrinfo", return_value=fake):
            self.assertIsNone(W.resolve_public("mdns.example"))
        fake6 = [(10, 1, 6, "", ("ff02::1", 0, 0, 0))]
        with mock.patch("bot.websearch.socket.getaddrinfo", return_value=fake6):
            self.assertIsNone(W.resolve_public("mc6.example"))


class PortalsAndButtons(unittest.TestCase):
    def test_catalogue(self):
        self.assertEqual(len(portals.PORTALS), 6)
        for key, (_, ar, en, items) in portals.PORTALS.items():
            self.assertTrue(ar and en and items, key)
            for name, a, n, url in items:
                self.assertTrue(name and a and n and url.startswith("https://"), (key, name))
        self.assertGreaterEqual(sum(len(v[3]) for v in portals.PORTALS.values()), 35)
        self.assertIn("lat=36.7500", portals.portal_url(36.75, 3.06))
        self.assertEqual(portals.portal_url(), "https://globe.adsbexchange.com")
        self.assertIn("openstreetmap", portals.portal_url(1, 2, "osm"))

    def test_webapp_button_structure(self):
        b = kb([[("Map", "webapp:https://globe.adsbexchange.com"), ("Link", "https://x.org"), ("Cb", "m:main")]])["inline_keyboard"][0]
        self.assertEqual(b[0], {"text": "Map", "web_app": {"url": "https://globe.adsbexchange.com"}})
        self.assertEqual(b[1], {"text": "Link", "url": "https://x.org"})
        self.assertEqual(b[2]["callback_data"], "m:main")

    def test_server_rejecting_web_app_gets_plain_links(self):
        api = TelegramAPI("T")
        sent = []

        def fake_call(method, timeout=30, files=None, **params):
            sent.append(params["reply_markup"])
            if any("web_app" in x for row in params["reply_markup"]["inline_keyboard"] for x in row):
                api._tl.last_error = "Bad Request: BUTTON_TYPE_INVALID web_app not supported"
                return None
            return {"message_id": 1}
        markup = kb([[("Map", "webapp:https://globe.adsbexchange.com")]])
        with mock.patch.object(api, "call", side_effect=fake_call):
            self.assertEqual(api.send_message(1, "x", markup), {"message_id": 1})
            self.assertFalse(api.webapp_ok)
            self.assertTrue(api.styles_ok)                                              # only Mini-App buttons were the problem
            api.send_message(1, "again", markup)
        self.assertEqual(sent[-1]["inline_keyboard"][0][0], {"text": "Map", "url": "https://globe.adsbexchange.com"})
        self.assertEqual(len(sent), 3)


class WorldFlows(Harness):
    __test__ = True

    def sent(self):
        return "\n".join(p.get("text", "") for m, p in ti.CALLS if m in ("sendMessage", "editMessageText"))

    def markup_buttons(self):
        return [b for m, p in ti.CALLS if m in ("sendMessage", "editMessageText") for row in (p.get("reply_markup") or {}).get("inline_keyboard", []) for b in row]

    def test_radar_output_and_open_in_telegram_button(self):
        ac = [S.norm_aircraft(a, (36.75, 3.06)) for a in AC["ac"][:2]]
        res = {"ok": True, "provider": "adsb.lol", "aircraft": sorted(ac, key=lambda a: a["dist_km"]), "radius_km": 185.2}
        with mock.patch("bot.skytools.aircraft_near", return_value=res), mock.patch("bot.skytools.geocode", return_value={"name": "Algiers", "country": "Algeria", "lat": 36.75, "lon": 3.06}):
            self.app.on_message(message(1, "/radar Algiers 100"))
        text = self.sent()
        self.assertIn("DAH1001", text)
        self.assertIn("<pre>", text)
        self.assertIn("🚨", text)                                                    # the 7700 squawk is flagged
        self.assertIn("ADS-B", text)
        self.assertTrue(any("web_app" in b and "adsbexchange" in b["web_app"]["url"] for b in self.markup_buttons()))
        self.assertTrue(any(a["action"] == "radar" for a in self.db.list_audit(10)))

    def test_radar_usage_and_unknown_place(self):
        self.app.on_message(message(1, "/radar"))
        self.assertIn("/radar", self.sent())
        with mock.patch("bot.skytools.geocode", return_value=None):
            self.app.on_message(message(1, "/radar Nowhereville"))
        self.assertIn("لم أجد هذا المكان", self.sent())

    def test_radar_radius_parsing_and_cap(self):
        calls = []

        def fake(lat, lon, radius_km, http=None):
            calls.append(radius_km)
            return {"ok": True, "provider": "x", "aircraft": [], "radius_km": radius_km}
        with mock.patch("bot.skytools.aircraft_near", side_effect=fake), mock.patch("bot.skytools.geocode", return_value={"name": "N", "country": "", "lat": 1, "lon": 2}):
            self.app.on_message(message(1, "/radar Algiers 80"))
            self.app.on_message(message(1, "/radar Algiers 999"))
            self.app.on_message(message(1, "/radar 36.75,3.06"))
        self.assertEqual(calls, [80.0, 400.0, 60.0])

    def test_radar_provider_failure_is_reported_politely(self):
        with mock.patch("bot.skytools.aircraft_near", return_value={"ok": False, "error": "x"}), mock.patch("bot.skytools.geocode", return_value={"name": "N", "country": "", "lat": 1, "lon": 2}):
            self.app.on_message(message(1, "/radar Algiers"))
        self.assertIn("تعذّر جلب البيانات", self.sent())

    def test_flight_plane_squawk(self):
        with mock.patch("bot.skytools.aircraft_lookup", return_value={"ok": True, "provider": "x", "aircraft": [S.norm_aircraft(AC["ac"][0])]}) as f:
            self.app.on_message(message(1, "/flight AH1001"))
            self.app.on_message(message(1, "/plane 0a1b2c"))
            self.app.on_message(message(1, "/plane 7T-VJA"))
            self.assertEqual([c.args[0] for c in f.call_args_list], ["callsign", "hex", "reg"])
            self.assertIn("DAH1001", self.sent())
            ti.CALLS.clear()
            self.app.on_message(message(1, "/squawk"))
            self.assertEqual(len(f.call_args_list), 6)                                # 7700, 7600, 7500
        self.assertIn("لا تفترض حادثاً فعلياً", self.sent())

    def test_invalid_flight_value_never_reaches_the_network(self):
        with mock.patch("bot.skytools._get") as g:
            self.app.on_message(message(1, "/flight ../../etc/passwd"))
            self.app.on_message(message(1, "/plane a/b"))
        self.assertFalse(g.called)
        self.assertIn("قيمة غير صالحة", self.sent())

    def test_metar_weather_iss_space_quakes_radio(self):
        m = {"ok": True, "icao": "DAAG", "name": "Algiers", "raw": "DAAG 1200Z 27010KT", "cat": "IFR", "temp": 20, "dewp": 10, "wdir": 270, "wspd": 10, "wgst": 25,
             "visib": "3", "altim": 1012, "time": "", "taf": "TAF DAAG"}
        w = {"ok": True, "current": {"temperature_2m": 21.0, "apparent_temperature": 20, "relative_humidity_2m": 50, "cloud_cover": 10, "precipitation": 0, "weather_code": 0,
                                     "wind_speed_10m": 12, "wind_direction_10m": 270, "wind_gusts_10m": 20, "pressure_msl": 1015, "visibility": 20000},
             "daily": {"time": ["2026-11-10", "2026-11-11"], "temperature_2m_max": [24, 23], "temperature_2m_min": [15, 14], "precipitation_sum": [0, 1], "weather_code": [0, 61]}, "tz": ""}
        with mock.patch("bot.skytools.metar", return_value=m), mock.patch("bot.skytools.weather", return_value=w), \
                mock.patch("bot.skytools.geocode", return_value={"name": "Algiers", "country": "Algeria", "lat": 36.7, "lon": 3.0}), \
                mock.patch("bot.skytools.iss", return_value={"ok": True, "lat": 10.0, "lon": 20.0, "alt_km": 420.0, "kmh": 27600.0, "visibility": "daylight"}), \
                mock.patch("bot.skytools.space_weather", return_value={"ok": True, "kp": 5.0, "sfi": 160.0, "scales": {"R": "1", "S": "0", "G": "2"}}), \
                mock.patch("bot.skytools.quakes", return_value={"ok": True, "feed": "4.5_day", "total": 1, "items": [{"mag": 6.2, "place": "Somewhere", "ts": 1.8e9, "depth": 10, "tsunami": True, "url": "", "lat": 1, "lon": 2}]}), \
                mock.patch("bot.skytools.radio_stations", return_value={"ok": True, "stations": [{"name": "Chaine 3", "url": "https://s/x", "country": "Algeria", "codec": "MP3", "bitrate": 128, "tags": "", "home": ""}]}):
            for cmd in ("/metar DAAG", "/weather Algiers", "/iss Algiers", "/space", "/quakes 4.5", "/radio DZ"):
                self.app.on_message(message(1, cmd))
        t = self.sent()
        for needle in ("🔴 فئة الطيران", "IFR", "TAF DAAG", "21.0°C", "27600", "Kp: <b>5.0</b>", "عاصفة مغناطيسية", "M6.2", "🌊", "Chaine 3"):
            self.assertIn(needle, t, needle)

    def test_offline_radio_tools(self):
        for cmd in ("/freq 121.5", "/freq 145.5 MHz", "/wave 145.5 MHz", "/morse SOS", "/morse ... --- ...", "/phonetic DZ73", "/qcode QTH", "/qcode",
                    "/grid 36.75,3.06", "/grid JM16", "/power 30dBm", "/fspl 145.5MHz 10km", "/horizon 30 2"):
            self.app.on_message(message(1, cmd))
        t = self.sent()
        for needle in ("تردد استغاثة", "Amateur 2 m".replace("Amateur 2 m", "هواة 2 متر"), "λ/4", "... --- ...", "SOS", "Delta · Zulu · Seven · Tree", "QTH", "رموز Q", "JM16",
                       "30.00 dBm", "dB</b>", "km</b>"):
            self.assertIn(needle, t, needle)

    def test_freq_rejects_garbage_and_dist_works(self):
        self.app.on_message(message(1, "/freq banana"))
        self.assertIn("تردد غير صالح", self.sent())
        with mock.patch("bot.skytools.geocode", side_effect=lambda q, http=None: {"name": q.strip(), "country": "", "lat": 36.75 if "Alg" in q else 48.85, "lon": 3.06 if "Alg" in q else 2.35}):
            self.app.on_message(message(1, "/dist Algiers -> Paris"))
        self.assertIn("1347 km", self.sent().replace(" km", " km"))

    def test_network_tools_refuse_private_targets_without_requests(self):
        with mock.patch("bot.netintel.requests.get") as g:
            for cmd in ("/asn 10.0.0.1", "/rdns 127.0.0.1", "/exposure 192.168.1.1", "/exposure localhost", "/mac zz", "/subdomains 1.2.3.4"):
                self.app.on_message(message(1, cmd))
        self.assertFalse(g.called)

    def test_network_tools_happy_paths(self):
        with mock.patch("bot.netintel.subdomains", return_value={"ok": True, "names": ["a.example.com", "b.example.com"], "count": 2}), \
                mock.patch("bot.netintel.asn_info", return_value={"ok": True, "ip": "8.8.8.8", "prefix": "8.8.8.0/24", "announced": True, "asn": 15169, "holder": "GOOGLE", "abuse": ["abuse@google.com"]}), \
                mock.patch("bot.netintel.reverse_dns", return_value={"ok": True, "ip": "8.8.8.8", "names": ["dns.google"]}), \
                mock.patch("bot.netintel.mac_vendor", return_value={"ok": True, "oui": "001A2B", "vendor": "Cisco", "random": False, "multicast": False}), \
                mock.patch("bot.netintel.exposure", return_value={"ok": True, "ip": "93.184.216.34", "known": True, "ports": [22, 443], "hostnames": [], "cpes": [], "vulns": ["CVE-2018-15473"], "tags": []}):
            for cmd in ("/subdomains example.com", "/asn 8.8.8.8", "/rdns 8.8.8.8", "/mac 00:1A:2B:3C:4D:5E", "/exposure 93.184.216.34"):
                self.app.on_message(message(1, cmd))
        t = self.sent()
        for needle in ("b.example.com", "AS<b>15169</b>", "dns.google", "Cisco", "CVE-2018-15473", "22, 443"):
            self.assertIn(needle, t, needle)
        self.assertTrue(all(any(a["action"] == act for a in self.db.list_audit(30)) for act in ("net_subdomains", "net_asn", "net_exposure")))

    def test_menus_and_direct_buttons(self):
        self.app.on_callback(cb(1, "m:world"))
        for want in ("t:radar", "t:flight", "t:metar", "wd:squawk", "wd:iss", "wd:space", "wd:quakes", "t:radio", "m:rf", "m:portals"):
            self.assertIn(want, self.buttons())
        self.app.on_callback(cb(1, "m:rf"))
        for want in ("t:freq", "t:morse", "t:grid", "t:fspl", "wd:qcode"):
            self.assertIn(want, self.buttons())
        self.app.on_callback(cb(1, "m:portals"))
        self.assertIn("pt:air", self.buttons())
        ti.CALLS.clear()
        self.app.on_callback(cb(1, "pt:air"))
        urls = [b["web_app"]["url"] for b in self.markup_buttons() if "web_app" in b]
        self.assertTrue(any("flightradar24" in u for u in urls))
        with mock.patch("bot.skytools.iss", return_value={"ok": True, "lat": 1.0, "lon": 2.0, "alt_km": 400.0, "kmh": 27000.0, "visibility": "x"}):
            self.app.on_callback(cb(1, "wd:iss"))
        self.assertIn("المحطة الفضائية", self.sent())

    def test_portal_buttons_are_plain_links_when_disabled(self):
        import dataclasses
        self.app.cfg = dataclasses.replace(self.app.cfg, webapp_buttons=False)
        self.app.on_callback(cb(1, "pt:radio"))
        self.assertFalse(any("web_app" in b for b in self.markup_buttons()))
        self.assertTrue(any(b.get("url", "").startswith("https://") for b in self.markup_buttons()))

    def test_input_flow_from_menu_and_main_menu_entry(self):
        self.app.on_callback(cb(1, "m:main"))
        self.assertIn("m:world", self.buttons())
        self.app.on_callback(cb(1, "t:freq"))
        self.app.on_message(message(1, "1090"))
        self.assertIn("ADS-B", self.sent())

    def test_non_allowed_user_cannot_use_world_tools(self):
        self.app.on_message(message(2, "hi"))
        with mock.patch("bot.skytools.aircraft_near") as a:
            self.app.on_message(message(2, "/radar Algiers"))
        self.assertFalse(a.called)

    def test_help_lists_new_commands(self):
        self.app.on_message(message(1, "/help"))
        for needle in ("/radar", "/squawk", "/exposure", "/portals"):
            self.assertIn(needle, self.sent())

    def test_every_new_command_is_registered_and_has_a_hint(self):
        from bot.ui import HINTS, WORLD_KINDS
        for k in WORLD_KINDS:
            self.assertIn(k, self.app.commands, k)
            self.assertIn(k, HINTS, k)


if __name__ == "__main__":
    unittest.main()
