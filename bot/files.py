"""Turn an answer into downloadable files: code files, ZIP project, TXT, MD, HTML, JSON, CSV."""
from __future__ import annotations

import csv
import html
import io
import json
import re
import time
import zipfile

MAX_FILES = 60
SKIP_DIRS = {"node_modules", ".git", "__pycache__", "venv", ".venv", "dist", "build", ".idea", "target"}
MAX_TOTAL = 8 * 1024 * 1024

EXT = {
    "python": "py", "py": "py", "python3": "py", "javascript": "js", "js": "js", "node": "js", "typescript": "ts",
    "ts": "ts", "jsx": "jsx", "tsx": "tsx", "bash": "sh", "sh": "sh", "shell": "sh", "zsh": "sh", "console": "sh",
    "powershell": "ps1", "ps1": "ps1", "bat": "bat", "cmd": "bat", "json": "json", "yaml": "yml", "yml": "yml",
    "toml": "toml", "ini": "ini", "html": "html", "css": "css", "scss": "scss", "sql": "sql", "c": "c",
    "cpp": "cpp", "c++": "cpp", "csharp": "cs", "cs": "cs", "java": "java", "kotlin": "kt", "swift": "swift",
    "go": "go", "golang": "go", "rust": "rs", "rs": "rs", "php": "php", "ruby": "rb", "rb": "rb", "lua": "lua",
    "perl": "pl", "r": "r", "xml": "xml", "markdown": "md", "md": "md", "csv": "csv", "text": "txt", "txt": "txt",
    "env": "env", "conf": "conf", "nginx": "conf", "diff": "diff", "dockerfile": "Dockerfile", "makefile": "Makefile",
    "vue": "vue", "dart": "dart", "scala": "scala", "asm": "asm", "regex": "txt", "sigma": "yml", "yara": "yar",
}
_FENCE = re.compile(r"```([^\n`]*)\n(.*?)```", re.S)
_NAME_RX = re.compile(r"^[`*_\s#>\-]*([\w][\w./\\-]*\.[A-Za-z0-9]{1,8}|Dockerfile|Makefile)[`*_\s:)\]]*$")
_COMMENT_NAME = re.compile(r"^\s*(?:#|//|--|/\*|<!--)\s*(?:file(?:name)?|path)\s*[:=]\s*([\w./\\-]+)", re.I)


def safe_name(name: str, fallback: str = "file.txt") -> str:
    """Make a filename safe for a ZIP/download: no absolute paths, no '..', no odd characters, bounded depth."""
    parts = []
    for seg in re.split(r"[\\/]+", (name or "").strip()):
        seg = re.sub(r"[^\w.\- ]", "_", seg).strip(" .")
        if seg and seg not in (".", ".."):
            parts.append(seg[:80])
    parts = parts[-4:]
    return "/".join(parts) or fallback


def extract_files(text: str) -> list:
    """Return [(name, content)] for every fenced code block, naming them from the fence, a header comment or the
    line just above the block, otherwise snippet-N.<ext>."""
    files, used, n = [], set(), 0
    for m in _FENCE.finditer(text or ""):
        info, body = m.group(1).strip(), m.group(2).rstrip("\n")
        if not body.strip():
            continue
        n += 1
        lang = (info.split() or [""])[0].lower().strip("{}")
        name = None
        mm = re.search(r"(?:file(?:name)?|title|path)\s*=\s*[\"']?([\w./\\-]+)", info, re.I)
        if mm:
            name = mm.group(1)
        elif "." in lang and re.fullmatch(r"[\w./\\-]+\.\w{1,8}", lang):
            name, lang = lang, ""
        if not name:
            first = body.split("\n", 1)[0]
            mc = _COMMENT_NAME.match(first)
            if mc:
                name = mc.group(1)
        if not name:
            above = (text[:m.start()].rstrip().split("\n") or [""])[-1]
            mn = _NAME_RX.match(above.strip())
            if mn:
                name = mn.group(1)
        if not name:
            ext = EXT.get(lang, "txt")
            name = ext if ext in ("Dockerfile", "Makefile") else f"snippet-{n}.{ext}"
        name = safe_name(name, f"snippet-{n}.txt")
        base, k = name, 2
        while name.lower() in used:
            stem, dot, ext = base.rpartition(".")
            name = f"{stem}_{k}.{ext}" if dot else f"{base}_{k}"
            k += 1
        used.add(name.lower())
        files.append((name, body + "\n"))
    return files


def make_zip(files: list, answer_md: str = "") -> bytes:
    """Build the archive in memory. Raises ValueError when too big or too many files."""
    if len(files) > MAX_FILES:
        raise ValueError("too many files")
    total = sum(len(c.encode("utf-8")) for _, c in files) + len(answer_md.encode("utf-8"))
    if total > MAX_TOTAL:
        raise ValueError("too large")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in files:
            z.writestr(safe_name(name), content)
        if answer_md:
            z.writestr("ANSWER.md", answer_md)
    return buf.getvalue()


def to_plain(text: str) -> str:
    out = []
    for line in (text or "").replace("\r\n", "\n").split("\n"):
        if line.strip().startswith("```"):
            continue
        line = re.sub(r"^\s{0,3}#{1,6}\s*", "", line)
        line = re.sub(r"(\*\*|__)(.+?)\1", r"\2", line)
        line = re.sub(r"`([^`]+)`", r"\1", line)
        line = re.sub(r"^\s*[*-]\s+", "• ", line)
        out.append(line)
    return re.sub(r"\n{3,}", "\n\n", "\n".join(out)).strip() + "\n"


def to_html_page(text: str, rendered_html: str, title: str = "DARWIN DZ") -> bytes:
    """Standalone, script-free page. `rendered_html` is the already-escaped Telegram-subset HTML of the answer."""
    body = rendered_html.replace("\n", "<br>\n")
    page = (f"<!doctype html><html dir=\"auto\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" "
            f"content=\"width=device-width,initial-scale=1\"><title>{html.escape(title)}</title><style>"
            "body{font:16px/1.7 system-ui,sans-serif;max-width:800px;margin:2rem auto;padding:0 1rem}"
            "pre,code{background:#8881;border-radius:6px;padding:.1em .4em;font-family:ui-monospace,monospace}"
            "pre{padding:1rem;overflow:auto;white-space:pre-wrap}blockquote{margin:1rem 0;padding:.2rem 1rem;"
            "border-inline-start:4px solid #4a90d9;background:#4a90d911}</style></head><body>"
            f"{body}</body></html>")
    return page.encode("utf-8")


def to_json(question: str, answer: str, files: list) -> bytes:
    data = {"created": time.strftime("%Y-%m-%dT%H:%M:%S"), "question": question, "answer": answer,
            "code_blocks": [{"name": n, "content": c} for n, c in files]}
    return json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")


def first_table_csv(text: str):
    """Convert the first Markdown table in `text` to CSV bytes (None when there is no table)."""
    lines = (text or "").split("\n")
    for i in range(len(lines) - 1):
        if "|" in lines[i] and re.match(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$", lines[i + 1]):
            rows, j = [lines[i]], i + 2
            while j < len(lines) and "|" in lines[j] and lines[j].strip():
                rows.append(lines[j])
                j += 1
            buf = io.StringIO()
            w = csv.writer(buf)
            for r in rows:
                cells = [c.strip().replace("**", "").replace("`", "") for c in r.strip().strip("|").split("|")]
                w.writerow(cells)
            return buf.getvalue().encode("utf-8-sig")
    return None


def read_zip_project(data: bytes, max_files: int = 80, per_file: int = 60_000, max_total: int = 600_000) -> str:
    """Read an uploaded project archive entirely in memory and return a tree + the text files' contents.
    Nothing is extracted to disk (no path traversal), entries are capped, binaries are skipped and the read size
    is bounded per entry so a zip bomb cannot exhaust memory. Raises ValueError/BadZipFile when unsafe."""
    z = zipfile.ZipFile(io.BytesIO(data))
    infos = z.infolist()
    if len(infos) > 3000 or sum(i.file_size for i in infos) > 80 * 1024 * 1024:
        raise ValueError("archive too large")
    tree, chunks, total, skipped = [], [], 0, 0
    for i in infos:
        if i.is_dir() or i.flag_bits & 0x1:                         # directories and encrypted entries
            continue
        parts = re.split(r"[\\/]+", i.filename)
        if i.filename.startswith(("/", "\\")) or ".." in parts or any(p in SKIP_DIRS for p in parts):
            skipped += 1
            continue
        name = safe_name(i.filename)
        tree.append(f"{name} ({i.file_size} B)")
        if len(chunks) >= max_files or total >= max_total or i.file_size > 500_000:
            skipped += 1
            continue
        raw = z.open(i).read(per_file + 1)
        if b"\x00" in raw[:2048]:                                   # binary
            skipped += 1
            continue
        text = raw[:per_file].decode("utf-8", "replace")
        total += len(text)
        cut = "\n…[truncated]" if len(raw) > per_file else ""
        chunks.append(f"--- {name} ---\n{text}{cut}")
    head = f"PROJECT ARCHIVE: {len(tree)} files" + (f" ({skipped} skipped)" if skipped else "") + "\n" + "\n".join(f"- {t}" for t in tree[:200])
    return head + "\n\n" + "\n\n".join(chunks)
