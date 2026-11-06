"""v4.0: deployment readiness — preflight check, permissions hardening, deploy scripts."""
import dataclasses
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from bot.config import Config
from bot.preflight import harden_data_permissions, render, run_preflight

ROOT = Path(__file__).resolve().parent.parent


class FakeTG:
    def __init__(self, me):
        self.me = me

    def get_me(self):
        return self.me


class Preflight(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.environ["API_KEY"] = "k"
        os.environ["TELEGRAM_TOKEN"] = "1:abc"
        self.addCleanup(lambda: [os.environ.pop(k, None) for k in ("API_KEY", "TELEGRAM_TOKEN")])
        self.cfg = dataclasses.replace(Config.from_env(), db_path=os.path.join(self.tmp, "data", "bot.db"),
                                       log_file=os.path.join(self.tmp, "data", "bot.log"), admin_ids=frozenset({1}))

    @staticmethod
    def reachable(addr, timeout):
        class S:
            def close(self):
                pass
        return S()

    @staticmethod
    def unreachable(addr, timeout):
        raise OSError(111, "Connection refused")

    def status(self, results, label):
        return next(s for s, l, _ in results if l.startswith(label))

    def test_ready_when_everything_works(self):
        res = run_preflight(self.cfg, FakeTG({"username": "bot", "can_read_all_group_messages": True}), self.reachable)
        self.assertFalse([r for r in res if r[0] == "fail"], res)
        self.assertIn("READY", render(res))
        self.assertTrue(Path(self.cfg.db_path).exists())

    def test_bad_token_and_no_network_fail(self):
        res = run_preflight(self.cfg, FakeTG(None), self.unreachable)
        self.assertEqual(self.status(res, "Telegram token"), "fail")
        self.assertEqual(self.status(res, "Network → api.telegram.org"), "fail")
        self.assertIn("NOT READY", render(res))

    def test_privacy_mode_and_missing_admin_are_warnings(self):
        cfg = dataclasses.replace(self.cfg, admin_ids=frozenset())
        res = run_preflight(cfg, FakeTG({"username": "bot", "can_read_all_group_messages": False}), self.reachable)
        self.assertEqual(self.status(res, "Telegram token"), "warn")
        self.assertEqual(self.status(res, "ADMIN_IDS"), "warn")
        self.assertIn("Privacy Mode", str([r for r in res if r[1] == "Telegram token"]))
        self.assertNotIn("NOT READY", render(res))

    def test_web_search_unreachable_is_only_a_warning(self):
        calls = []

        def connect(addr, timeout):
            calls.append(addr[0])
            if "duckduckgo" in addr[0]:
                raise OSError("no route")
            return self.reachable(addr, timeout)
        res = run_preflight(self.cfg, FakeTG({"username": "b"}), connect)
        self.assertEqual(self.status(res, "Network → web search"), "warn")
        self.assertFalse([r for r in res if r[0] == "fail"])

    def test_unwritable_data_folder_fails(self):
        if os.geteuid() == 0:
            self.skipTest("root can write anywhere")
        ro = os.path.join(self.tmp, "ro")
        os.mkdir(ro, 0o500)
        cfg = dataclasses.replace(self.cfg, db_path=os.path.join(ro, "sub", "bot.db"))
        self.assertEqual(self.status(run_preflight(cfg, None, self.reachable), "Data folder"), "fail")


class Permissions(unittest.TestCase):
    def test_data_files_become_private(self):
        tmp = tempfile.mkdtemp()
        d = Path(tmp, "data")
        d.mkdir(mode=0o755)
        for name in ("bot.db", "bot.db-wal", "bot.log"):
            (d / name).write_text("x")
            os.chmod(d / name, 0o644)
        cfg = dataclasses.replace(Config.from_env(), db_path=str(d / "bot.db"), log_file=str(d / "bot.log"))
        harden_data_permissions(cfg)
        self.assertEqual(stat.S_IMODE(os.stat(d).st_mode), 0o700)
        for name in ("bot.db", "bot.db-wal", "bot.log"):
            self.assertEqual(stat.S_IMODE(os.stat(d / name).st_mode), 0o600, name)


class DeployKit(unittest.TestCase):
    def test_scripts_parse_and_are_executable(self):
        for name in ("install_vps.sh", "backup.sh", "run_tmux.sh"):
            p = ROOT / "deploy" / name
            self.assertTrue(os.access(p, os.X_OK), name)
            self.assertEqual(subprocess.run(["bash", "-n", str(p)]).returncode, 0, name)

    def test_service_is_sandboxed_and_restarts(self):
        unit = (ROOT / "deploy" / "darwin.service").read_text()
        for needed in ("Restart=always", "User=darwin", "NoNewPrivileges=true", "ProtectSystem=strict",
                       "ReadWritePaths=/opt/darwin_dz/data", "KillSignal=SIGTERM", "UMask=0077"):
            self.assertIn(needed, unit)
        self.assertNotIn("User=root", unit)

    def test_backup_script_makes_a_valid_private_copy(self):
        tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(tmp, "data"))
        os.makedirs(os.path.join(tmp, "venv", "bin"))
        os.symlink(sys.executable, os.path.join(tmp, "venv", "bin", "python"))
        from bot.storage import Storage
        s = Storage(os.path.join(tmp, "data", "bot.db"))
        s.upsert_user(7, "u", "U")
        s.close()
        r = subprocess.run(["bash", str(ROOT / "deploy" / "backup.sh")], env={**os.environ, "APP_DIR": tmp},
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        copies = list(Path(tmp, "data", "backups").glob("bot-*.db"))
        self.assertEqual(len(copies), 1)
        self.assertEqual(stat.S_IMODE(os.stat(copies[0]).st_mode), 0o600)
        s2 = Storage(str(copies[0]))
        self.assertEqual(s2.get_user(7)["username"], "u")
        s2.close()

    def test_check_flag_never_prints_the_token(self):
        tmp = tempfile.mkdtemp()
        env = {**os.environ, "TELEGRAM_TOKEN": "123456:SECRETTOKENxyz", "API_KEY": "SECRETKEYabc",
               "DB_PATH": os.path.join(tmp, "x.db"), "LOG_FILE": os.path.join(tmp, "x.log"),
               "TELEGRAM_API_URL": "http://127.0.0.1:9", "API_BASE_URL": "http://127.0.0.1:9", "WEB_SEARCH": "false"}
        r = subprocess.run([sys.executable, "main.py", "--check"], cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
        out = r.stdout + r.stderr
        self.assertNotIn("SECRETTOKENxyz", out)
        self.assertNotIn("SECRETKEYabc", out)
        self.assertIn("RESULT:", r.stdout)
        self.assertEqual(r.returncode, 1)                                  # nothing listens on port 9


if __name__ == "__main__":
    unittest.main()
