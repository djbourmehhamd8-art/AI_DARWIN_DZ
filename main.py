#!/usr/bin/env python3
from __future__ import annotations

import logging
import os
import signal
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from bot import __version__
from bot.ai_client import AIClient
from bot.config import Config, load_env
from bot.handlers import BotApp
from bot.logsafe import RedactFilter
from bot.preflight import harden_data_permissions, render, run_preflight
from bot.storage import Storage
from bot.telegram import TelegramAPI


def setup_logging(cfg: Config) -> None:
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    root = logging.getLogger()
    root.setLevel(getattr(logging, cfg.log_level, logging.INFO))
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root.addHandler(sh)
    Path(cfg.log_file).parent.mkdir(parents=True, exist_ok=True)
    fh = RotatingFileHandler(cfg.log_file, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(fh)
    # never write the Telegram token / API key to the console or the log file (requests puts URLs in errors)
    flt = RedactFilter([cfg.telegram_token, *cfg.all_keys()])
    sh.addFilter(flt)
    fh.addFilter(flt)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def _warn_env_permissions() -> None:
    """The .env file holds the bot token and API key: it should not be readable by other users."""
    try:
        mode = Path(".env").stat().st_mode
        if mode & 0o077:
            logging.getLogger("bot").warning(".env is readable by other users, run: chmod 600 .env")
    except OSError:
        pass


def main() -> int:
    os.umask(0o077)                                  # everything the bot creates (database, logs) is private to its user
    load_env()
    cfg = Config.from_env()
    if "--check" in sys.argv[1:]:                    # preflight: python main.py --check
        quiet = logging.StreamHandler()              # library errors contain the request URL, i.e. the bot token
        quiet.addFilter(RedactFilter([cfg.telegram_token, *cfg.all_keys()]))
        quiet.setLevel(logging.ERROR)
        logging.getLogger().addHandler(quiet)
        tg = TelegramAPI(cfg.telegram_token, cfg.telegram_api_url) if cfg.telegram_token.strip() else None
        results = run_preflight(cfg, tg)
        if tg:
            tg.close()
        print(render(results))
        return 1 if any(s == "fail" for s, _, _ in results) else 0
    problems = cfg.validate()
    if problems:
        print("Config error:", "; ".join(problems), "\nCopy .env.example to .env and fill it in.")
        return 1
    setup_logging(cfg)
    harden_data_permissions(cfg)
    _warn_env_permissions()
    logging.getLogger("bot").info("DARWIN DZ v%s", __version__)

    db = Storage(cfg.db_path)
    tg = TelegramAPI(cfg.telegram_token, cfg.telegram_api_url)
    ai = AIClient(cfg.api_base_url, cfg.all_keys(), cfg.model, cfg.ai_timeout, cfg.ai_retries, cfg.workers * 2,
              cfg.key_strategy)
    app = BotApp(cfg, tg, ai, db)

    def shutdown(*_):
        app.stop.set()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    try:
        app.run()
    except RuntimeError as e:
        logging.getLogger("bot").error("%s", e)
        return 1
    finally:
        # Close every persistent HTTP/SQLite resource on normal shutdown and startup failure.
        ai.close()
        tg.close()
        db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
