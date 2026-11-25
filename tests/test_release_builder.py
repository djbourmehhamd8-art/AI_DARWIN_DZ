import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.build_release import build


class ReleaseBuilderTests(unittest.TestCase):
    def test_release_excludes_secrets_databases_and_caches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src"
            (root / "bot").mkdir(parents=True)
            (root / "data").mkdir()
            (root / ".ruff_cache").mkdir()
            (root / "bot" / "__init__.py").write_text('__version__ = "9.8.7"\n')
            (root / "bot" / "module.py").write_text("safe = True\n")
            (root / ".env").write_text("TOKEN=secret\n")
            (root / "data" / "bot.db").write_bytes(b"database")
            (root / "data" / ".gitkeep").write_text("")
            (root / ".ruff_cache" / "junk").write_text("cache")
            out = Path(tmp) / "release.zip"
            info = build(out, root)
            self.assertEqual(info["version"], "9.8.7")
            with zipfile.ZipFile(out) as archive:
                names = archive.namelist()
                self.assertIn("darwin_dz/bot/module.py", names)
                self.assertIn("darwin_dz/data/.gitkeep", names)
                self.assertIn("darwin_dz/RELEASE-MANIFEST.json", names)
                self.assertFalse(any(n.endswith(".db") or n.endswith("/.env") or ".ruff_cache" in n for n in names))
                manifest = json.loads(archive.read("darwin_dz/RELEASE-MANIFEST.json"))
                self.assertIn("bot/module.py", manifest["files"])
                self.assertEqual(
                    hashlib.sha256(archive.read("darwin_dz/bot/module.py")).hexdigest(),
                    manifest["files"]["bot/module.py"],
                )

    def test_rebuild_has_no_duplicate_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src"
            (root / "bot").mkdir(parents=True)
            (root / "bot" / "__init__.py").write_text('__version__ = "1.0.0"\n')
            (root / "RELEASE-MANIFEST.json").write_text("{}")
            out = Path(tmp) / "release.zip"
            build(out, root)
            with zipfile.ZipFile(out) as archive:
                names = archive.namelist()
                self.assertEqual(names.count("darwin_dz/RELEASE-MANIFEST.json"), 1)
                self.assertNotIn("RELEASE-MANIFEST.json", json.loads(archive.read("darwin_dz/RELEASE-MANIFEST.json"))["files"])

    def test_release_keeps_scripts_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src"
            (root / "bot").mkdir(parents=True)
            (root / "bot" / "__init__.py").write_text('__version__ = "1.0.0"\n')
            (root / "run.sh").write_text("#!/usr/bin/env bash\necho ok\n")
            (root / "tool.py").write_text("#!/usr/bin/env python3\nprint(1)\n")
            (root / "plain.py").write_text("x = 1\n")
            out = Path(tmp) / "release.zip"
            build(out, root)
            with zipfile.ZipFile(out) as archive:
                def mode(name):
                    return (archive.getinfo(f"darwin_dz/{name}").external_attr >> 16) & 0o777
                self.assertEqual(mode("run.sh"), 0o755)
                self.assertEqual(mode("tool.py"), 0o755)
                self.assertEqual(mode("plain.py"), 0o644)
                self.assertEqual(mode("RELEASE-MANIFEST.json"), 0o644)


if __name__ == "__main__":
    unittest.main()
