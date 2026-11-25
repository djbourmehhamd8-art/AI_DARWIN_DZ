#!/usr/bin/env python3
"""Robustness fuzzer: throws hostile input at every offline tool and bot command and fails on anything unexpected.

    python scripts/fuzz.py            # full run (about 30 s)
    python scripts/fuzz.py --quick    # CI smoke run (about 8 s)

A tool may reject input with ValueError (that is the contract). Any other exception, or a call slower than the budget,
is a bug. Network commands are skipped so the run is deterministic and offline.
"""
from __future__ import annotations

import logging
import random
import signal
import string
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bot.webext import WEB_TOOLS, run_web_tool  # noqa: E402

SLOW_SECONDS = 0.5
NETWORK_COMMANDS = frozenset("""radar flight plane squawk metar weather radio iss space quakes domain dns whois cert webhead footprint
subdomains asn rdns exposure websearch dist stop start broadcast backup panel web groupusage system export""".split())


def hostile_inputs(n_random: int, seed: int = 7) -> list:
    rnd = random.Random(seed)
    alphabet = string.printable + "ءآأبتثجحخ\u202e\u0000\U0001F600"
    fixed = ["", " ", "\n" * 50, "a" * 20000, "." * 20000, "a." * 10000, "(" * 5000, "1" * 5000, "9" * 400 + "^9" * 50, "%" * 3000,
             "=" * 5000, ";" * 5000, "a=b;" * 3000, "0" * 3000 + "/24", "10.0.0.0/8 /" + "9" * 50, "* * * * *" + " " * 5000, "\\" * 5000,
             "http://" + "a." * 5000, "A" * 64, "-" * 5000, "e" * 5000 + "@" + "x" * 5000, "eyJ." * 3000, "CVSS:3.1/" + "AV:N/" * 2000,
             "[" * 3000 + "]" * 3000, "Bearer " + "a" * 100000, "password=" + "a" * 100000, "v=spf1 " + "a:x " * 5000 + "-all",
             "u=rwx," * 3000, "10.0.0.1 in " + ", ".join(f"10.{i}.0.0/16" for i in range(300)), "a\n---\n" + "b\n" * 5000]
    return fixed + ["".join(rnd.choice(alphabet) for _ in range(rnd.randint(1, 300))) for _ in range(n_random)]


def fuzz_web_tools(n_random: int) -> list:
    problems = []
    for kind, _ in WEB_TOOLS:
        for text in hostile_inputs(n_random):
            started = time.perf_counter()
            try:
                run_web_tool(kind, text)
            except ValueError:
                pass
            except Exception as e:                                           # noqa: BLE001 - anything else is the bug we hunt
                problems.append(f"web tool {kind!r}: {type(e).__name__}: {str(e)[:60]} <- {text[:30]!r}")
            took = time.perf_counter() - started
            if took > SLOW_SECONDS:
                problems.append(f"web tool {kind!r}: {took:.2f}s on {text[:30]!r}")
    return problems


def fuzz_bot_commands(n_random: int) -> list:
    from tests.test_ui import message
    from tests.test_v34 import Harness
    problems: list = []

    class Run(Harness):
        __test__ = True

        def test_fuzz(self):
            self.db.upsert_user(1, "admin", "Admin")

            class Timeout(Exception):
                pass

            def on_alarm(*_):
                raise Timeout()
            signal.signal(signal.SIGALRM, on_alarm)
            for name in sorted(self.app.commands):
                if name in NETWORK_COMMANDS:
                    continue
                for arg in hostile_inputs(n_random, seed=3)[:60 + n_random]:
                    signal.alarm(8)
                    started = time.perf_counter()
                    try:
                        self.app.on_message(message(1, f"/{name} {arg}"))
                        if time.perf_counter() - started > 2:
                            problems.append(f"/{name}: {time.perf_counter() - started:.1f}s (slow) on {arg[:30]!r}")
                    except Timeout:
                        problems.append(f"/{name}: timeout on {arg[:30]!r}")
                    except Exception as e:                                   # noqa: BLE001
                        problems.append(f"/{name}: {type(e).__name__}: {str(e)[:60]} <- {arg[:30]!r}")
                    finally:
                        signal.alarm(0)

    logging.disable(logging.CRITICAL)
    suite = unittest.TestLoader().loadTestsFromTestCase(Run)
    unittest.TextTestRunner(stream=open("/dev/null", "w"), verbosity=0).run(suite)
    logging.disable(logging.NOTSET)
    return problems


def main() -> int:
    quick = "--quick" in sys.argv[1:]
    n = 10 if quick else 120
    started = time.time()
    problems = fuzz_web_tools(n) + fuzz_bot_commands(5 if quick else 25)
    for p in sorted(set(problems))[:40]:
        print("FAIL", p)
    print(f"fuzz: {len(WEB_TOOLS)} web tools, {'quick' if quick else 'full'} run, {len(set(problems))} problem(s), {time.time() - started:.0f}s")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
