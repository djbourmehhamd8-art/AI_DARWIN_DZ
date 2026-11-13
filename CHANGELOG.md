# Changelog

Newest first. Full notes per version are in `docs/changelog/`.

## Versions
- **[4.3.0](docs/changelog/CHANGELOG_4.3.0.md)** — Live world: aircraft radar, radio, space, web portals
- **[4.2.0](docs/changelog/CHANGELOG_4.2.0.md)** — Conversation manners, advanced tools, verified answers
- **[4.1.0](docs/changelog/CHANGELOG_4.1.0.md)** — Strict groups, daily limits, resilient web search, GitHub-ready
- **[4.0.0](docs/changelog/CHANGELOG_4.0.0.md)** — Audited, deployment-ready release (FadeHost / any VPS)
- **[3.9.0](docs/changelog/CHANGELOG_3.9.0.md)** — Private-bot access, groups, multi-level admin
- **[3.8.0](docs/changelog/CHANGELOG_3.8.0.md)** — Full audit release
- **[3.7.0](docs/changelog/CHANGELOG_3.7.0.md)** — Web search, file export, expert mode
- **[3.6.0](docs/changelog/CHANGELOG_3.6.0.md)** — Admin panel, colours, security fix
- **[3.5.0](docs/changelog/CHANGELOG_3.5.0.md)** — Answer quality release
- **[3.4.0](docs/changelog/CHANGELOG_3.4.0.md)** — Organisation release
- **[3.3.0](docs/changelog/CHANGELOG_3.3.0.md)** — DARWIN DZ 3.3.0
- **[3.2.3](docs/changelog/CHANGELOG_3.2.3.md)** — Expert response tuning and regression fix
- **[3.2.1](docs/changelog/CHANGELOG_3.2.1.md)** — Reliability and configuration hardening

---

## 4.3.0 (latest) — Live world: aircraft radar, radio, space, web portals

## ✈️ Aircraft radar (public ADS-B)
- `/radar <city|lat,lon> [km]` — aircraft around a place: a **text radar scope** (north up, rings, numbered contacts), a list with
  callsign, type, flight level, speed, heading, distance and compass direction, plus a button that opens the live map **inside Telegram**.
- `/flight <callsign>`, `/plane <registration|hex>`, and `/squawk` for aircraft squawking **7700 / 7600 / 7500** (general emergency,
  radio failure, hijack — with a reminder that a code can be a mistake or a drill).
- Two independent feeds (adsb.lol → airplanes.live), 8-second cache and a 1 req/s gap per host; every input is validated before it enters a URL.
  The bot says plainly that the data is crowd-sourced, can be delayed or incomplete, and is **never for navigation or safety**.

## 🌦 Weather, space and Earth
- `/metar <ICAO>` (flight category 🟢🔵🔴🟣, wind, visibility, QNH + TAF), `/weather <city>` (now + 3 days, Arabic/English conditions),
  `/iss [city]` (position, altitude, speed, distance to you, map button), `/space` (Kp, solar flux, NOAA R/S/G scales and a rough **HF propagation outlook**),
  `/quakes [min magnitude]` (USGS, tsunami flag).

## 📻 Radio communications
- `/radio <name|country code>` internet radio (e.g. `/radio DZ`) with stream links.
- Offline calculators: `/freq` (what lives on a frequency: bands, aviation/marine distress, ADS-B 1090, ISS 145.800, APRS, weather satellites, GNSS, ISM/LoRa, Wi-Fi…),
  `/wave` (wavelength, dipole and quarter-wave lengths), `/morse` (both ways), `/phonetic` (NATO), `/qcode` (31 codes incl. QNH/QFE/QNE),
  `/grid` (Maidenhead ⇄ coordinates), `/power` (dBm ⇄ W), `/fspl` (free-space path loss), `/horizon` (radio horizon), `/dist` (distance, bearing, locators).
  Allocations are ITU Region 1 at a general level; the bot reminds users to check their national regulator before transmitting.
- Tools guide: new **Radio, SDR & reception** category (RTL-SDR, SDR++, GNU Radio, readsb/tar1090, WSJT-X, SatDump…).

## 🧬 More passive security intelligence
- `/subdomains` (certificate-transparency logs, nothing sent to the target), `/asn` (network, holder, abuse contact via RIPEstat),
  `/rdns`, `/mac` (only the 3-byte OUI leaves the bot; flags randomised addresses), `/exposure` (what Shodan InternetDB already knows about *your* IP/domain:
  ports, CPEs, CVEs — and the bot nudges you to verify each CVE). All refuse private/internal targets without making a request.

## 🧭 Web portals inside the bot
- `/portals` (and 🌍 World → portals): **39 live sites in 6 categories** — aviation radar, ships, space, radio receivers (WebSDR, KiwiSDR, Radio Garden),
  weather/Earth, and live cyber-threat maps. In private chats the buttons are **Mini-App buttons that open inside Telegram**; groups get ordinary links.
  If a server rejects Mini-App buttons the bot falls back to plain links automatically (`WEBAPP_BUTTONS=false` forces links).
- New **🌍 Live world** entry in the main menu with every tool one tap away, plus a **radio toolbox** screen.

## 🔐 Hardening found while testing
- The stdlib treats **multicast** addresses as "global": `224.0.0.1` passed our public-address check. Both the page-fetch guard and the new
  network tools now refuse multicast.

## Tests
`python -m unittest discover -s tests -t .` — new `tests/test_v43.py` (51 tests): maths against known values (FSPL, Maidenhead IO91wm, haversine), feed fallbacks, input validation, private-target refusal, Mini-App fallback.
