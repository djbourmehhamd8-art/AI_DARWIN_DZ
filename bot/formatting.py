"""Markdown (as written by LLMs) -> Telegram HTML, plus fence-aware splitting for the 4096-char limit.

Telegram only understands a small HTML subset (b, i, s, a, code, pre, blockquote). This module converts
headings, bold/italic/strike, links, lists, quotes, rules and tables into that subset, closes code fences that
the model left open, and guarantees the result has balanced tags (otherwise it falls back to escaped text),
so a message is never rejected with "can't parse entities".
"""
from __future__ import annotations

import html
import re

_FENCE = re.compile(r"```[ \t]*([\w+#.-]*)[ \t]*\n?(.*?)```", re.S)
_FENCE_OPEN = re.compile(r"```([\w+#.-]*)")
_CODE_SPAN = re.compile(r"`([^`\n]+)`")
_LINK = re.compile(r"\[([^\]\n]{1,200})\]\((https?://[^\s)]{1,800}|tg://[^\s)]{1,200}|mailto:[^\s)]{1,200})\)")
_BOLD = re.compile(r"\*\*(?=\S)(.+?)(?<=\S)\*\*|__(?=\S)(.+?)(?<=\S)__")
_ITALIC_STAR = re.compile(r"(?<![\w*\\])\*(?=[^\s*])(.+?)(?<=[^\s*])\*(?![\w*])")
_ITALIC_UNDER = re.compile(r"(?<!\w)_(?=[^\s_])(.+?)(?<=[^\s_])_(?!\w)")
_STRIKE = re.compile(r"~~(?=\S)(.+?)(?<=\S)~~")
_HEADING = re.compile(r"^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$")
_HR = re.compile(r"^\s*([-*_])(?:\s*\1){2,}\s*$")
_QUOTE = re.compile(r"^\s{0,3}>\s?(.*)$")
_BULLET = re.compile(r"^(\s*)[-*+•]\s+(.*)$")
_ORDERED = re.compile(r"^(\s*)(\d{1,3})[.)]\s+(.*)$")
_TASK = re.compile(r"^\[( |x|X)\]\s+(.*)$")
_TABLE_SEP = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$")
_TAG = re.compile(r"<(/?)(b|i|s|a|code|pre|blockquote)\b[^>]*>")
_ANY_TAG = re.compile(r"<[^>]+>")

INDENT = "\u2003"          # em space: survives Telegram's whitespace trimming
RULE = "──────────"


# --------------------------------------------------------------------------------------------- helpers
def _balanced(h: str) -> bool:
    stack = []
    for m in _TAG.finditer(h):
        closing, name = m.group(1), m.group(2)
        if not closing:
            stack.append(name)
        elif not stack or stack.pop() != name:
            return False
    return not stack


def visible_len(h: str) -> int:
    """Length Telegram counts for an HTML message (tags removed, entities decoded)."""
    return len(html.unescape(_ANY_TAG.sub("", h)))


def has_markup(h: str) -> bool:
    return re.search(r"<(b|i|s|a|code|pre|blockquote)\b", h) is not None


def _strip_md(s: str) -> str:
    s = _CODE_SPAN.sub(r"\1", s)
    s = _LINK.sub(r"\1", s)
    s = re.sub(r"(\*\*|__|~~)", "", s)
    return s.strip()


def _inline(s: str) -> str:
    """Inline Markdown of one line -> HTML. Code spans are protected from every other rule."""
    codes: list = []

    def stash(m):
        codes.append(m.group(1))
        return f"\x00{len(codes) - 1}\x00"

    s = _CODE_SPAN.sub(stash, s)
    esc = html.escape(s, quote=False)

    def link(m):
        url = m.group(2).replace('"', "%22")
        return f'<a href="{url}">{m.group(1)}</a>'

    out = _LINK.sub(link, esc)
    out = _BOLD.sub(lambda m: f"<b>{m.group(1) or m.group(2)}</b>", out)
    out = _STRIKE.sub(r"<s>\1</s>", out)
    out = _ITALIC_STAR.sub(r"<i>\1</i>", out)
    out = _ITALIC_UNDER.sub(r"<i>\1</i>", out)
    if not _balanced(out):                                  # crossed emphasis: keep it as plain text
        out = esc
    return re.sub(r"\x00(\d+)\x00", lambda m: f"<code>{html.escape(codes[int(m.group(1))], quote=False)}</code>", out)


def _cells(line: str) -> list:
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    return [_strip_md(c) for c in line.split("|")]


def _render_table(rows: list) -> str:
    """Tables do not fit a phone: 2 columns become `• key — value`, wider ones become one block per row."""
    head, body = _cells(rows[0]), [_cells(r) for r in rows[2:]]
    out = []
    for r in body:
        r = (r + [""] * len(head))[:len(head)]
        if len(head) == 2:
            out.append(f"• <b>{html.escape(r[0], quote=False)}</b> — {html.escape(r[1], quote=False)}")
        else:
            out.append(f"▪️ <b>{html.escape(r[0], quote=False)}</b>")
            for label, val in zip(head[1:], r[1:]):
                if val:
                    out.append(f"{INDENT}{html.escape(label, quote=False)}: {html.escape(val, quote=False)}")
    if len(head) == 2 and head[0] and head[1]:
        out.insert(0, f"<b>{html.escape(head[0], quote=False)} / {html.escape(head[1], quote=False)}</b>")
    return "\n".join(out)


def _render_text(seg: str) -> str:
    lines = seg.split("\n")
    out: list = []
    i = 0
    while i < len(lines):
        line = lines[i]
        # table: header row + separator row + body rows
        if "|" in line and i + 1 < len(lines) and _TABLE_SEP.match(lines[i + 1]) and "-" in lines[i + 1]:
            j = i + 2
            while j < len(lines) and "|" in lines[j] and lines[j].strip():
                j += 1
            out.append(_render_table(lines[i:j]))
            i = j
            continue
        m = _QUOTE.match(line)
        if m:
            quoted = []
            while i < len(lines) and _QUOTE.match(lines[i]):
                quoted.append(_inline(_QUOTE.match(lines[i]).group(1)))
                i += 1
            tag = "<blockquote expandable>" if len(quoted) >= 4 else "<blockquote>"      # long quotes collapse on the phone
            out.append(tag + "\n".join(quoted) + "</blockquote>")
            continue
        m = _HEADING.match(line)
        if m:
            title = _strip_md(m.group(2)) if m.group(2) else ""
            if title:
                if out and out[-1] != "":
                    out.append("")                          # breathing room before a section title
                out.append(f"<b>{html.escape(title, quote=False)}</b>")
            i += 1
            continue
        if _HR.match(line) and not _BULLET.match(line):
            out.append(RULE)
            i += 1
            continue
        m = _BULLET.match(line)
        if m:
            level = min(len(m.group(1).replace("\t", "  ")) // 2, 3)
            body = m.group(2)
            t = _TASK.match(body)
            mark = ("•", "◦", "▪", "▫")[level]
            if t:
                mark, body = ("☑" if t.group(1) in "xX" else "☐"), t.group(2)
            out.append(f"{INDENT * level}{mark} {_inline(body)}")
            i += 1
            continue
        m = _ORDERED.match(line)
        if m:
            level = min(len(m.group(1).replace("\t", "  ")) // 2, 3)
            out.append(f"{INDENT * level}{m.group(2)}. {_inline(m.group(3))}")
            i += 1
            continue
        out.append(_inline(line))
        i += 1
    return "\n".join(out)


def close_open_fence(text: str) -> str:
    """A model that stops mid-code-block (or is cut by /stop) leaves an odd number of ``` fences."""
    if text.count("```") % 2:
        return text.rstrip("\n") + "\n```"
    return text


def to_html(text: str) -> str:
    """Convert common Markdown (code blocks, inline code, emphasis, headings, lists, quotes, tables, links)."""
    text = close_open_fence(tidy_answer(text.replace("\r\n", "\n")))
    out, pos = [], 0
    for m in _FENCE.finditer(text):
        out.append(_render_text(text[pos:m.start()]))
        lang, body = m.group(1), html.escape(m.group(2).rstrip("\n"), quote=False)
        if lang:
            out.append(f'<pre><code class="language-{html.escape(lang)}">{body}</code></pre>')
        else:
            out.append(f"<pre>{body}</pre>")
        pos = m.end()
    out.append(_render_text(text[pos:]))
    res = "".join(out)
    res = re.sub(r"\n{3,}", "\n\n", res)
    return res.strip("\n")


# ------------------------------------------------------------------------------------- answer clean-up
# Only pure pleasantries are removed. Words that can BE the answer ("Absolutely.", "Certainly not.", "تمام") are never
# touched, and cheerful openers are removed only when written with "!" and followed by real content.
_FILLER_OPEN = re.compile(
    r"^\s*(?:(?:great|good|excellent) question|happy to help|sure thing|here you go"
    r"|سؤال (?:ممتاز|جيد|رائع)|بكل سرور|يسعدني مساعدتك)\s*[!.:،,]+(?:[ \t]*\n+|[ \t]+(?=\S))"
    r"|^\s*(?:sure|certainly|of course|بالتأكيد|بالطبع)\s*!+(?:[ \t]*\n+|[ \t]+(?=\S))", re.I)
_FILLER_CLOSE = re.compile(
    r"\n+\s*(?:i hope this helps[^\n]*|let me know if you (?:need|have|want) (?:anything|any|more|further)[^\n]*"
    r"|feel free to (?:ask|reach out)[^\n]*|hope that helps[^\n]*"
    r"|(?:آمل|أتمنى) أن (?:يكون|تكون|ينفعك|يفيدك)[^\n]*"
    r"|لا تتردد في (?:سؤالي|السؤال|طرح|الاستفسار|التواصل)[^\n]*)\s*$", re.I)


def tidy_answer(text: str) -> str:
    """Remove chatty filler at the very start/end of an answer ("Great question!", "I hope this helps").
    Never touches code blocks, never removes anything that could be the actual answer, never empties a reply."""
    if not text or "```" in text[:60]:
        return text
    t = text.replace("\r\n", "\n")
    m = _FILLER_OPEN.match(t)
    if m and len(t) - m.end() > 20:
        t = t[m.end():]
        if t[:1].isascii():
            t = t[:1].upper() + t[1:]
    if "```" not in t[-80:]:
        m = _FILLER_CLOSE.search(t)
        if m and m.start() > 20:
            t = t[:m.start()]
    return t.strip("\n") if t.strip() else text


# --------------------------------------------------------------------------------------------- splitting
def _cut_point(body: str, limit: int) -> int:
    for sep in ("\n\n", "\n", " "):
        cut = body.rfind(sep, limit // 2, limit)
        if cut > 0:
            return cut + (len(sep) if sep != " " else 1)
    return limit


def split_md(text: str, limit: int = 3200) -> list:
    """Split Markdown into chunks <= limit. A cut inside a code block closes it and reopens it in the next chunk."""
    text = close_open_fence(text)
    if len(text) <= limit:
        return [text]
    chunks, carry, rest = [], "", text
    while True:
        body = carry + rest
        if len(body) <= limit:
            chunks.append(body)
            return chunks
        cut = _cut_point(body, limit - 8)
        piece, rest = body[:cut].rstrip("\n"), body[cut:].lstrip("\n")
        opens = _FENCE_OPEN.findall(piece)
        if len(opens) % 2:                                  # we are inside a code block at the cut
            carry = f"```{opens[-1]}\n"
            piece += "\n```"
        else:
            carry = ""
        chunks.append(piece)


def render_chunks(text: str, limit: int = 3200) -> list:
    """Return [(markdown, html)] where every html part is within Telegram's limit and has balanced tags."""
    out = []
    for md in split_md(text, limit):
        h = to_html(md)
        if visible_len(h) > 4000 and limit > 400:           # lists/tables can expand: split this chunk smaller
            out.extend(render_chunks(md, limit * 2 // 3))
        else:
            out.append((md, h))
    return out
