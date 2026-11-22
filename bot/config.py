from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import math
from urllib.parse import urlsplit
from dataclasses import dataclass
from pathlib import Path

from .utils import safe_int


def load_env(path: str = ".env") -> None:
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8-sig").splitlines():     # utf-8-sig: a BOM (Windows/phone editors) must not rename the first key
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip()
        if v[:1] in ('"', "'"):
            q = v[0]
            end = v.find(q, 1)
            v = v[1:end] if end > 0 else v[1:]                       # KEY="value"  # comment  -> value
        else:
            v = re.split(r"\s+#", v, maxsplit=1)[0].strip()         # KEY=value  # comment
        k = k.strip()
        if k.startswith("export "):
            k = k[7:].strip()
        if k:
            os.environ.setdefault(k, v)


def clean_token(value: str) -> str:
    """Telegram tokens pasted into hosting panels often carry spaces, quotes or a leading 'bot'."""
    v = (value or "").strip().strip("\"'`").strip()
    if v.lower().startswith("bot") and ":" in v[3:]:
        v = v[3:]
    return "".join(v.split())


def first_env(*names: str) -> str:
    """First non-empty environment variable among several accepted names."""
    for n in names:
        v = os.environ.get(n, "").strip()
        if v:
            return v
    return ""


def derive_panel_password(telegram_token: str) -> str:
    """Web panel password when WEB_PANEL_TOKEN is not set: derived from the bot token, so it needs no extra setting,
    survives restarts and redeploys, and changes automatically when the bot token is rotated. Admins get it from /web."""
    if not telegram_token:
        return ""
    mac = hmac.new(telegram_token.encode("utf-8"), b"darwin-dz-web-panel-v1", hashlib.sha256).digest()
    return base64.b32encode(mac)[:20].decode("ascii").lower()


def _ids(value: str) -> frozenset:
    out = set()
    for x in value.replace(" ", "").split(","):
        n = safe_int(x)
        if n is not None:
            out.add(n)
    return frozenset(out)


def _bool(value: str, default: bool) -> bool:
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _num(value: str, default, cast):
    try:
        return cast(value) if value != "" else default
    except ValueError:
        return default


@dataclass(frozen=True)
class Config:
    telegram_token: str
    api_key: str
    api_keys: tuple = ()
    key_strategy: str = "failover"
    api_base_url: str = "https://api.aiwithnorestrictions.com/v1"
    model: str = "notrack-uncensored:bare"
    telegram_api_url: str = "https://api.telegram.org"
    admin_ids: frozenset = frozenset()
    allowed_ids: frozenset = frozenset()
    public: bool = True                # True = anyone not banned can use the bot (no access requests); False = private bot
    db_path: str = "data/bot.db"
    log_file: str = "data/bot.log"
    log_level: str = "INFO"
    max_history: int = 20
    max_context_chars: int = 60000
    max_input_chars: int = 8000
    rate_limit: int = 12
    stream: bool = True
    stream_interval: float = 1.0
    workers: int = 8
    default_lang: str = "ar"
    default_temp: float = 0.7
    system_prompt: str = ""
    price_in: float = 0.15
    price_out: float = 0.50
    daily_limit: int = 0
    new_user_limit: int = 50           # daily messages given automatically to every NEW user (and on approval) (0 = off)
    web_panel_port: int = 0            # web user-management panel: 0 = off, else the local port (needs WEB_PANEL_TOKEN)
    web_panel_host: str = "127.0.0.1"  # bind address; keep 127.0.0.1 unless you put HTTPS in front of it
    web_panel_token: str = ""          # the panel password (at least 12 characters)
    web_panel_hosts: tuple = ()        # extra Host names accepted when the panel sits behind a reverse proxy
    web_panel_url: str = ""            # public HTTPS address of the web panel, e.g. https://laplace.fadehost.com (adds the admin-panel button)
    groups: bool = True                # answer in groups (each group must be authorised unless GROUP_OPEN)
    group_open: bool = False           # True = answer in ANY group without authorisation
    group_triggers: tuple = ("dz", "دي زد")
    group_member_limit: int = 30       # daily questions for members of an authorised group who have no personal access
    contact: str = "DARWIN0DZ"         # owner account shown on the access screen
    secret_guard: bool = True
    hibp: bool = True
    ai_timeout: int = 120
    ai_retries: int = 2
    default_persona: str = "default"
    retention_days: int = 0
    digest_hour: int = -1              # local hour (0-23) for the daily admin report; -1 = off
    group_daily_limit: int = 0         # default messages per GROUP per day (0 = unlimited); admins can set it per group
    brave_api_key: str = ""            # optional: reliable web search (free key at brave.com/search/api)
    searxng_url: str = ""              # optional: your own SearXNG instance, e.g. https://searx.example.org
    osint: bool = True                 # /footprint (public handle existence check); admins can switch it at runtime
    cve_ground: bool = True            # look up CVE ids in NVD/EPSS/KEV and give the model the verified facts
    nvd_api_key: str = ""              # optional NVD key (higher rate limit)
    webapp_buttons: bool = True        # portal/map buttons open inside Telegram (private chats); plain links elsewhere
    web_search: bool = True            # global switch for web-grounded answers
    web_default: str = "auto"          # default per-user mode: off | auto | on
    web_results: int = 5
    web_pages: int = 2                 # how many result pages to read for excerpts (0 = snippets only)

    def web_panel_hostnames(self) -> tuple:
        """Host names the panel accepts: WEB_PANEL_HOSTS plus the host of WEB_PANEL_URL."""
        extra = ()
        if self.web_panel_url:
            u = urlsplit(self.web_panel_url)
            if u.hostname:
                extra = (u.hostname.lower(), (u.hostname.lower() + ":" + str(u.port)) if u.port else u.hostname.lower())
        return tuple(dict.fromkeys(self.web_panel_hosts + extra))

    def ai_keys(self) -> list:
        """ONLY the AI provider keys: these (and nothing else) may be sent to API_BASE_URL."""
        from .keypool import parse_keys
        return parse_keys(self.api_keys, self.api_key)

    def all_keys(self) -> list:
        """Every secret value (AI keys + Brave + NVD + panel password). For log redaction ONLY, never for requests."""
        return self.ai_keys() + [k for k in (self.brave_api_key, self.nvd_api_key,
                                                                  self.web_panel_token if (self.web_panel_port or self.web_panel_token != derive_panel_password(self.telegram_token)) else "") if k]

    @classmethod
    def from_env(cls) -> "Config":
        e = os.environ.get
        from .keypool import parse_keys
        lang = e("DEFAULT_LANG", "ar")
        numbered = [os.environ[k] for k in sorted(os.environ, key=lambda x: (len(x), x))
                    if k.startswith("API_KEY_") and k[8:].isdigit()]
        keys = parse_keys(e("API_KEY", ""), e("API_KEYS", ""), numbered)
        tg_token = clean_token(first_env("TELEGRAM_TOKEN", "TELEGRAM_BOT_TOKEN", "BOT_TOKEN", "TOKEN"))
        hosted_port = _num(e("PORT", ""), 0, int)                    # hosting platforms give the app a port to listen on
        panel_port = _num(e("WEB_PANEL_PORT", ""), 0, int) or hosted_port
        panel_host = e("WEB_PANEL_HOST", "").strip() or ("0.0.0.0" if hosted_port else cls.web_panel_host)
        panel_token = e("WEB_PANEL_TOKEN", "").strip()
        if len(panel_token) < 12:                                    # missing or too short: never crash, derive a strong one
            panel_token = derive_panel_password(tg_token)
        return cls(
            telegram_token=tg_token,
            api_key=keys[0] if keys else "",
            api_keys=tuple(keys),
            key_strategy=e("KEY_STRATEGY", "failover").strip().lower(),
            api_base_url=e("API_BASE_URL", cls.api_base_url).rstrip("/"),
            model=(lambda m, persona: m if m.rsplit(":", 1)[-1] in
                   ("bare", "notrack", "concise", "detailed", "creative") else
                   (m + (":" + persona if persona in
                    ("bare", "notrack", "concise", "detailed", "creative") else ""))
                   )(e("MODEL", "notrack-uncensored").strip(),
                     e("API_PERSONA", "bare").strip().lower()),
            telegram_api_url=e("TELEGRAM_API_URL", cls.telegram_api_url).rstrip("/"),
            admin_ids=_ids(e("ADMIN_IDS", "")),
            allowed_ids=_ids(e("ALLOWED_IDS", "")),
            public=_bool(e("PUBLIC", ""), True),
            db_path=e("DB_PATH", cls.db_path),
            log_file=e("LOG_FILE", cls.log_file),
            log_level=e("LOG_LEVEL", cls.log_level).upper(),
            max_history=_num(e("MAX_HISTORY", ""), cls.max_history, int),
            max_context_chars=_num(e("MAX_CONTEXT_CHARS", ""), cls.max_context_chars, int),
            max_input_chars=_num(e("MAX_INPUT_CHARS", ""), cls.max_input_chars, int),
            rate_limit=_num(e("RATE_LIMIT", ""), cls.rate_limit, int),
            stream=_bool(e("STREAM", ""), True),
            stream_interval=_num(e("STREAM_INTERVAL", ""), cls.stream_interval, float),
            workers=_num(e("WORKERS", ""), cls.workers, int),
            default_lang=lang if lang in ("ar", "en") else "ar",
            default_temp=_num(e("DEFAULT_TEMP", ""), cls.default_temp, float),
            system_prompt=e("SYSTEM_PROMPT", ""),
            price_in=_num(e("PRICE_IN", ""), cls.price_in, float),
            price_out=_num(e("PRICE_OUT", ""), cls.price_out, float),
            daily_limit=_num(e("DAILY_LIMIT", ""), cls.daily_limit, int),
            new_user_limit=max(0, _num(e("NEW_USER_LIMIT", ""), cls.new_user_limit, int)),
            web_panel_port=max(0, panel_port),
            web_panel_host=panel_host,
            web_panel_token=panel_token,
            web_panel_hosts=tuple(h.strip().lower() for h in e("WEB_PANEL_HOSTS", "").split(",") if h.strip()),
            web_panel_url=first_env("WEB_PANEL_URL", "PUBLIC_URL", "APP_URL").rstrip("/"),
            groups=_bool(e("GROUPS", ""), True),
            group_open=_bool(e("GROUP_OPEN", ""), False),
            group_triggers=tuple(w.strip() for w in e("GROUP_TRIGGERS", "dz,دي زد").split(",") if w.strip()) or ("dz",),
            group_member_limit=max(0, _num(e("GROUP_MEMBER_LIMIT", ""), cls.group_member_limit, int)),
            contact=(e("CONTACT", cls.contact).strip().lstrip("@") or cls.contact),
            secret_guard=_bool(e("SECRET_GUARD", ""), True),
            hibp=_bool(e("HIBP", ""), True),
            ai_timeout=_num(e("AI_TIMEOUT", ""), cls.ai_timeout, int),
            ai_retries=_num(e("AI_RETRIES", ""), cls.ai_retries, int),
            default_persona=e("DEFAULT_PERSONA", cls.default_persona),
            retention_days=_num(e("RETENTION_DAYS", ""), cls.retention_days, int),
            digest_hour=max(-1, min(_num(e("DIGEST_HOUR", ""), -1, int), 23)),
            group_daily_limit=max(0, _num(e("GROUP_DAILY_LIMIT", ""), 0, int)),
            brave_api_key=e("BRAVE_API_KEY", "").strip(),
            searxng_url=(e("SEARXNG_URL", "").strip().rstrip("/") if e("SEARXNG_URL", "").strip().startswith(("http://", "https://")) else ""),
            osint=_bool(e("OSINT", ""), True),
            cve_ground=_bool(e("CVE_GROUNDING", ""), True),
            nvd_api_key=e("NVD_API_KEY", "").strip(),
            webapp_buttons=_bool(e("WEBAPP_BUTTONS", ""), True),
            web_search=_bool(e("WEB_SEARCH", ""), True),
            web_default=(e("WEB_DEFAULT", "auto").strip().lower() if e("WEB_DEFAULT", "auto").strip().lower() in ("off", "auto", "on") else "auto"),
            web_results=max(1, min(_num(e("WEB_RESULTS", ""), cls.web_results, int), 10)),
            web_pages=max(0, min(_num(e("WEB_PAGES", ""), cls.web_pages, int), 4)),
        )

    def validate(self) -> list:
        """Validate configuration before opening databases or starting worker threads."""
        problems = []
        if not self.telegram_token.strip():
            problems.append("TELEGRAM_TOKEN missing (also accepted: TELEGRAM_BOT_TOKEN, BOT_TOKEN, TOKEN)")
        if not self.ai_keys():
            problems.append("API_KEY / API_KEYS missing")

        for name, value in (("API_BASE_URL", self.api_base_url),
                            ("TELEGRAM_API_URL", self.telegram_api_url)):
            try:
                parsed = urlsplit(value)
                if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.username or parsed.password:
                    raise ValueError
                _ = parsed.port  # validates malformed ports
            except (TypeError, ValueError):
                problems.append(f"{name} must be a valid http(s) URL without embedded credentials")

        if self.key_strategy not in ("failover", "roundrobin"):
            problems.append("KEY_STRATEGY must be failover or roundrobin")
        if self.log_level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            problems.append("LOG_LEVEL must be DEBUG, INFO, WARNING, ERROR or CRITICAL")
        for name, value, low, high in (
            ("WORKERS", self.workers, 1, 64),
            ("MAX_HISTORY", self.max_history, 1, 200),
            ("MAX_CONTEXT_CHARS", self.max_context_chars, 1000, 1_000_000),
            ("MAX_INPUT_CHARS", self.max_input_chars, 100, 100_000),
            ("RATE_LIMIT", self.rate_limit, 1, 600),
            ("AI_TIMEOUT", self.ai_timeout, 5, 600),
            ("AI_RETRIES", self.ai_retries, 0, 5),
            ("RETENTION_DAYS", self.retention_days, 0, 3650),
            ("DAILY_LIMIT", self.daily_limit, 0, 1_000_000),
            ("NEW_USER_LIMIT", self.new_user_limit, 0, 1_000_000),
        ):
            if not isinstance(value, int) or not low <= value <= high:
                problems.append(f"{name} must be between {low} and {high}")
        for name, value, low, high in (
            ("DEFAULT_TEMP", self.default_temp, 0.0, 2.0),
            ("STREAM_INTERVAL", self.stream_interval, 0.0, 10.0),
        ):
            if not isinstance(value, (int, float)) or not math.isfinite(value) or not low <= value <= high:
                problems.append(f"{name} must be between {low} and {high}")
        if self.web_panel_port:
            if not 1 <= self.web_panel_port <= 65535:
                problems.append("WEB_PANEL_PORT must be between 1 and 65535")
            if self.telegram_token and len(self.web_panel_token) < 12:
                problems.append("WEB_PANEL_TOKEN must be at least 12 characters when WEB_PANEL_PORT is set")
        if self.web_panel_url:
            u = urlsplit(self.web_panel_url)
            if u.scheme not in ("https", "http") or not u.hostname or u.username or u.password:
                problems.append("WEB_PANEL_URL must look like https://your-domain (no user:password)")
        if (not math.isfinite(self.price_in) or not math.isfinite(self.price_out)
                or self.price_in < 0 or self.price_out < 0):
            problems.append("PRICE_IN and PRICE_OUT must be finite, non-negative numbers")
        return problems
