"""Offline CVSS v3.0/v3.1 base-score calculator (FIRST specification)."""
from __future__ import annotations

import math
import re

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
_NAMES = {
    "AV": ("الهجوم عبر", "Attack vector", {"N": ("الشبكة", "Network"), "A": ("شبكة مجاورة", "Adjacent"),
                                          "L": ("محلي", "Local"), "P": ("فيزيائي", "Physical")}),
    "AC": ("تعقيد الهجوم", "Complexity", {"L": ("منخفض", "Low"), "H": ("مرتفع", "High")}),
    "PR": ("الصلاحيات المطلوبة", "Privileges", {"N": ("لا شيء", "None"), "L": ("منخفضة", "Low"), "H": ("عالية", "High")}),
    "UI": ("تفاعل المستخدم", "User interaction", {"N": ("لا", "None"), "R": ("مطلوب", "Required")}),
    "S": ("النطاق", "Scope", {"U": ("دون تغيير", "Unchanged"), "C": ("متغيّر", "Changed")}),
    "C": ("السرية", "Confidentiality", {"N": ("لا أثر", "None"), "L": ("منخفض", "Low"), "H": ("عالٍ", "High")}),
    "I": ("السلامة", "Integrity", {"N": ("لا أثر", "None"), "L": ("منخفض", "Low"), "H": ("عالٍ", "High")}),
    "A": ("التوفر", "Availability", {"N": ("لا أثر", "None"), "L": ("منخفض", "Low"), "H": ("عالٍ", "High")}),
}
REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def severity(score: float) -> str:
    return "none" if score == 0 else "low" if score < 4 else "medium" if score < 7 else "high" if score < 9 else "critical"


def parse(vector: str):
    v = vector.strip().strip("()")
    v = re.sub(r"^CVSS:3\.[01]/", "", v, flags=re.I)
    metrics = {}
    for part in v.split("/"):
        k, _, val = part.partition(":")
        metrics[k.strip().upper()] = val.strip().upper()
    for k in REQUIRED:
        allowed = _PR["U"] if k == "PR" else _W.get(k) or {"U": 0, "C": 0}
        if metrics.get(k) not in allowed:
            return None
    return {k: metrics[k] for k in REQUIRED}


def calculate(vector: str) -> dict:
    m = parse(vector)
    if m is None:
        return {"ok": False}
    changed = m["S"] == "C"
    iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["I"][m["I"]]) * (1 - _W["A"][m["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * _PR["C" if changed else "U"][m["PR"]] * _W["UI"][m["UI"]]
    if impact <= 0:
        score = 0.0
    else:
        score = roundup(min((1.08 if changed else 1.0) * (impact + expl), 10))
    return {"ok": True, "score": score, "level": severity(score), "metrics": m}


def describe(res: dict, lang: str) -> str:
    i = 0 if lang == "ar" else 1
    icon = {"none": "⚪", "low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}[res["level"]]
    label = {"ar": {"none": "لا شيء", "low": "منخفضة", "medium": "متوسطة", "high": "عالية", "critical": "حرجة"},
             "en": {"none": "None", "low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}}[lang]
    head = f"{icon} CVSS 3.x: {res['score']:.1f} — {label[res['level']]}"
    lines = [head]
    for k in REQUIRED:
        name = _NAMES[k]
        lines.append(f"• {name[i]}: {name[2][res['metrics'][k]][i]}")
    lines.append("ℹ️ " + ("الدرجة الأساسية فقط؛ قيّم الخطر الفعلي حسب بيئتك." if lang == "ar"
                          else "Base score only; weigh real risk against your environment."))
    return "\n".join(lines)
