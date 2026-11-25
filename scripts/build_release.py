#!/usr/bin/env python3
"""Build a clean DARWIN DZ source release without runtime data or local secrets."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_DIRS = {".git", ".ruff_cache", "__pycache__", ".pytest_cache", ".mypy_cache", ".tox", "venv", ".venv"}
EXCLUDED_NAMES = {".env", "bot.db", "bot.db-wal", "bot.db-shm"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".log", ".db", ".sqlite", ".sqlite3"}


def file_mode(path: Path) -> int:
    """0o755 for scripts (shebang or .sh), 0o644 otherwise, so the archive keeps them runnable."""
    if path.suffix == ".sh":
        return 0o755
    try:
        with path.open("rb") as handle:
            return 0o755 if handle.read(2) == b"#!" else 0o644
    except OSError:
        return 0o644


def version(root: Path = ROOT) -> str:
    source = (root / "bot" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', source, re.M)
    if not match:
        raise ValueError("cannot determine package version")
    return match.group(1)


def safe_files(root: Path = ROOT):
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(root)
        if any(part in EXCLUDED_DIRS for part in rel.parts):
            continue
        if rel.as_posix() == "RELEASE-MANIFEST.json":   # regenerated on every build
            continue
        if path.name in EXCLUDED_NAMES or path.suffix.lower() in EXCLUDED_SUFFIXES:
            continue
        if path.name.startswith(".env.") and path.name != ".env.example":
            continue
        if rel.parts[:1] == ("data",) and rel.as_posix() != "data/.gitkeep":
            continue
        yield path, rel.as_posix()


def build(output: Path, root: Path = ROOT) -> dict:
    files = list(safe_files(root))
    if not files:
        raise ValueError("release contains no files")
    manifest = {
        "name": "DARWIN DZ",
        "version": version(root),
        "format": 1,
        "files": {name: hashlib.sha256(path.read_bytes()).hexdigest() for path, name in files},
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path, name in files:
            info = zipfile.ZipInfo(f"darwin_dz/{name}", date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | file_mode(path)) << 16
            archive.writestr(info, path.read_bytes())
        info = zipfile.ZipInfo("darwin_dz/RELEASE-MANIFEST.json", date_time=(2020, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        archive.writestr(info, json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    return {"version": manifest["version"], "files": len(files), "bytes": output.stat().st_size,
            "sha256": hashlib.sha256(output.read_bytes()).hexdigest(), "output": str(output)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", help="output ZIP path (default: ../darwin_dz_<version>.zip)")
    args = parser.parse_args(argv)
    ver = version()
    target = Path(args.output).expanduser() if args.output else ROOT.parent / f"darwin_dz_{ver.replace('.', '_')}.zip"
    result = build(target.resolve())
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
