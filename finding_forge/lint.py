"""Pre-submit lint for drafted vulnerability reports.

Three families of checks, printed as a concise checklist:

* **Sections** - every section a triager expects is present and non-empty.
* **Secrets & PII** - leaked tokens/keys/headers/PANs and unredacted PII in
  the report body (you paste real traffic in here; this is your seatbelt).
* **Quality** - a parseable CVSS vector, enumerated repro steps, and no
  vague filler or unresolved ``<TODO>`` placeholders.

Errors fail the gate (non-zero exit). Warnings pass by default and fail
under ``--strict`` (recommended for CI). Everything is regex + a little
Shannon entropy — no network, no external dependencies.
"""

from __future__ import annotations

import math
import re
from collections import namedtuple

from . import cvss

Check = namedtuple("Check", "level kind category message line")


class LintResult:
    """Accumulates checks and answers the pass/fail question."""

    def __init__(self):
        self.checks = []

    def add(self, level, kind, category, message, line=None):
        self.checks.append(Check(level, kind, category, message, line))

    @property
    def errors(self):
        return [c for c in self.checks if c.level == "error"]

    @property
    def warnings(self):
        return [c for c in self.checks if c.level == "warn"]

    @property
    def passes(self):
        return [c for c in self.checks if c.level == "ok"]

    def ok(self, strict=False):
        if self.errors:
            return False
        if strict and self.warnings:
            return False
        return True

    def exit_code(self, strict=False):
        return 0 if self.ok(strict) else 1


# --------------------------------------------------------------------------
# Required / recommended sections (canonical name -> accepted heading aliases)
# --------------------------------------------------------------------------

REQUIRED_SECTIONS = [
    ("Summary", ("summary", "overview", "description")),
    ("Affected Asset", ("affected asset", "affected assets", "affected endpoint",
                        "affected component", "affected url", "affected")),
    ("CVSS", ("cvss", "severity", "cvss score", "severity / cvss")),
    ("Impact", ("impact", "security impact", "business impact")),
    ("Steps to Reproduce", ("steps to reproduce", "reproduction steps",
                            "reproduction", "steps", "repro",
                            "how to reproduce")),
    ("Proof of Concept", ("proof of concept", "poc", "proof-of-concept")),
    ("Remediation", ("remediation", "mitigation", "fix", "recommendation",
                     "recommendations", "suggested fix", "how to fix")),
]
RECOMMENDED_SECTIONS = [
    ("References", ("references", "reference", "links")),
]

_HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
_COMMENT = re.compile(r"<!--.*?-->", re.S)
_PLACEHOLDER_STRIP = re.compile(
    r"<todo\b[^>]*>|<fill\b[^>]*>|<\.\.\.>|<[a-z][^>]{0,60}>", re.I
)


def _split_sections(text):
    """Return ``(preamble_lines, [(level, norm_title, raw_title, body_str)])``.

    Headings inside fenced code blocks are ignored.
    """
    lines = text.splitlines()
    sections = []
    preamble = []
    current = None
    in_fence = False
    fence = None
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            marker = stripped[:3]
            if not in_fence:
                in_fence, fence = True, marker
            elif stripped.startswith(fence):
                in_fence, fence = False, None
            (current[3] if current else preamble).append(line)
            continue
        m = None if in_fence else _HEADING.match(line)
        if m:
            raw = m.group(2).strip()
            current = [len(m.group(1)), raw.lower(), raw, []]
            sections.append(current)
        else:
            (current[3] if current else preamble).append(line)
    return preamble, [(lv, nm, rw, "\n".join(body)) for lv, nm, rw, body in sections]


def _find_section(sections, aliases):
    for _lv, norm, _raw, body in sections:
        for alias in aliases:
            if norm == alias or norm.startswith(alias + " ") or norm.startswith(alias):
                return body
    return None


def _is_empty(body):
    if body is None:
        return True
    cleaned = _COMMENT.sub(" ", body)
    cleaned = _PLACEHOLDER_STRIP.sub(" ", cleaned)
    # Drop list markers, numbering, blockquote/heading markers, code fences.
    cleaned = re.sub(r"(?m)^\s*(?:[-*+]|\d+[.)]|>|#{1,6}|`{3,}|~{3,})\s*", " ", cleaned)
    cleaned = cleaned.replace("`", " ")
    return not cleaned.strip()


# --------------------------------------------------------------------------
# Secret / PII detection
# --------------------------------------------------------------------------

# High-signal, structural secrets -> error.
_STRUCTURAL = [
    ("JWT token", re.compile(
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}")),
    ("AWS access key id", re.compile(
        r"\b(?:AKIA|ASIA|AROA|AIDA|AGPA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\b")),
    ("Private key block", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("GitHub token", re.compile(
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Stripe secret key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b")),
    ("Slack webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+")),
    ("Generic API key assignment", re.compile(
        r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret)"
        r"\b\s*[:=]\s*(?P<val>\S+)")),
]

# Header-style credentials -> error unless the value is clearly redacted.
_HEADER_PATTERNS = [
    ("Authorization header", re.compile(
        r"(?i)\bauthorization\s*:\s*(?P<val>\S.*)")),
    ("Cookie header", re.compile(
        r"(?i)\b(?:set-)?cookie\s*:\s*(?P<val>\S+=\S+)")),
    ("Bearer token", re.compile(r"(?i)\bbearer\s+(?P<val>[A-Za-z0-9._-]{12,})")),
    ("Basic auth credentials", re.compile(
        r"(?i)\bbasic\s+(?P<val>[A-Za-z0-9+/]{16,}={0,2})")),
]

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_EMAIL_ALLOW = re.compile(
    r"(?i)@(?:example\.(?:com|org|net)|[^@\s]*\.example|localhost"
    r"|[^@\s]*\.test|[^@\s]*\.invalid|sample\.com|email\.com)$")

_FILLER = re.compile(
    r"(?i)\b(might|maybe|could possibly|possibly|i think|i guess|not sure"
    r"|unsure|perhaps|somehow|hopefully|i believe|kind of|sort of)\b")

_PLACEHOLDER_LEFT = re.compile(
    r"<todo\b[^>]*>|<fill\b[^>]*>|<\.\.\.>|\bTODO\b|\bFIXME\b|\bXXX\b")

_PAN_CANDIDATE = re.compile(r"(?<![\d-])(?:\d[ -]?){13,19}(?![\d-])")
_ENTROPY_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{32,}")

_REDACTED = re.compile(
    r"(?i)^(?:redacted|placeholder|example|changeme|hunter2|token|secret"
    r"|password|your[_-]?\w*|session|cookie|value|<.*>|x{3,}|\*{3,}|\.{3,})$")


def _is_redacted(value):
    v = value.strip().strip("\"'`;,)>")
    if not v:
        return True
    # Any template/shell placeholder marker means "not a real secret".
    if any(ch in v for ch in "<${"):
        return True
    # Look at the token that carries the entropy (after `key=` for cookies).
    tail = v.split("=", 1)[-1].strip("\"'`;,")
    for token in (v, tail):
        if _REDACTED.match(token):
            return True
    return False


def _shannon_entropy(s):
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _luhn_ok(digits):
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _snippet(text, keep=12):
    text = text.strip()
    if len(text) <= keep * 2:
        return text[:keep] + ("..." if len(text) > keep else "")
    return "%s...%s" % (text[:keep], text[-4:])


def _scan_line(result, lineno, line):
    """Run all body-content checks against a single line."""
    seen = set()

    def flag(level, kind, category, detail):
        key = (kind, category, detail)
        if key in seen:
            return
        seen.add(key)
        result.add(level, kind, category, detail, lineno)

    for label, rx in _STRUCTURAL:
        for m in rx.finditer(line):
            val = m.groupdict().get("val")
            if val is not None and _is_redacted(val):
                continue
            flag("error", "secret", label, _snippet(m.group(0)))

    for label, rx in _HEADER_PATTERNS:
        for m in rx.finditer(line):
            if _is_redacted(m.group("val")):
                continue
            flag("error", "secret", label, _snippet(m.group(0)))

    for m in _PAN_CANDIDATE.finditer(line):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            flag("error", "secret", "Payment card number (Luhn-valid)",
                 _snippet(m.group(0)))

    for m in _EMAIL.finditer(line):
        if _EMAIL_ALLOW.search(m.group(0)):
            continue
        flag("warn", "pii", "Email address", m.group(0))

    for m in _ENTROPY_TOKEN.finditer(line):
        tok = m.group(0)
        if _is_redacted(tok):
            continue
        if _shannon_entropy(tok) >= 4.3:
            flag("warn", "secret", "High-entropy string (possible secret)",
                 _snippet(tok))

    for m in _FILLER.finditer(line):
        flag("warn", "quality", "Vague filler", '"%s"' % m.group(0))

    for m in _PLACEHOLDER_LEFT.finditer(line):
        flag("warn", "quality", "Unresolved placeholder", m.group(0))


# --------------------------------------------------------------------------
# CVSS presence
# --------------------------------------------------------------------------

_CVSS_IN_TEXT = re.compile(
    r"(?:CVSS:3\.[01]/)?"
    r"AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]",
    re.I,
)


def _check_cvss(result, text):
    matches = _CVSS_IN_TEXT.findall(text)
    if not matches:
        result.add("error", "cvss", "CVSS vector",
                   "no CVSS v3.1 base vector found in the report")
        return
    raw = matches[0].upper()
    try:
        score, rating, _ = cvss.score_vector(raw)
    except cvss.CVSSError as exc:
        result.add("error", "cvss", "CVSS vector",
                   "vector present but does not parse: %s" % exc)
        return
    result.add("ok", "cvss", "CVSS vector",
               "%s = %.1f (%s)" % (
                   raw if raw.startswith("CVSS") else "CVSS:3.1/" + raw,
                   score, rating))


# --------------------------------------------------------------------------
# Public entry points
# --------------------------------------------------------------------------

def lint_text(text):
    """Lint report ``text`` and return a :class:`LintResult`."""
    result = LintResult()
    _preamble, sections = _split_sections(text)

    # Title: an H1 that is non-empty and not just a placeholder.
    title = next((raw for lv, _n, raw, _b in sections if lv == 1), None)
    if not title or _is_empty(title):
        result.add("error", "section", "Title",
                   "missing or empty H1 title (`# ...`)")
    else:
        result.add("ok", "section", "Title", _snippet(title, 40))

    for name, aliases in REQUIRED_SECTIONS:
        body = _find_section(sections, aliases)
        if body is None:
            result.add("error", "section", name, "required section missing")
        elif _is_empty(body):
            result.add("error", "section", name,
                       "section is present but empty / only placeholders")
        else:
            result.add("ok", "section", name, "present")

    for name, aliases in RECOMMENDED_SECTIONS:
        body = _find_section(sections, aliases)
        if body is None or _is_empty(body):
            result.add("warn", "section", name,
                       "recommended section missing or empty")
        else:
            result.add("ok", "section", name, "present")

    # Enumerated repro steps (quality, not a hard gate).
    repro = _find_section(sections, (
        "steps to reproduce", "reproduction steps", "reproduction",
        "steps", "repro", "how to reproduce"))
    if repro and not _is_empty(repro):
        if not re.search(r"(?m)^\s*(?:\d+[.)]|[-*+])\s+\S", repro):
            result.add("warn", "quality", "Repro steps",
                       "steps are not enumerated (use a numbered list)")

    # Body scan for secrets / PII / filler / placeholders.
    for i, line in enumerate(text.splitlines(), start=1):
        _scan_line(result, i, line)

    _check_cvss(result, text)
    return result


def lint_file(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return lint_text(fh.read())


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

_SYMBOL = {"ok": "PASS", "warn": "WARN", "error": "FAIL"}
_GROUPS = [
    ("section", "Sections"),
    ("secret", "Secrets & PII"),
    ("pii", "Secrets & PII"),
    ("quality", "Quality"),
    ("cvss", "CVSS"),
]


def format_report(result, source="report", strict=False, show_ok=True):
    """Render a :class:`LintResult` as a concise, human-readable checklist."""
    lines = ["finding-forge lint - %s" % source, ""]
    order = ["Sections", "Secrets & PII", "Quality", "CVSS"]
    by_group = {g: [] for g in order}
    kind_to_group = {k: g for k, g in _GROUPS}
    for c in result.checks:
        by_group[kind_to_group.get(c.kind, "Quality")].append(c)

    for group in order:
        checks = by_group[group]
        if not checks:
            continue
        clean = all(c.level == "ok" for c in checks)
        # The secrets group is noisy when healthy: collapse to one summary line.
        secrets_summary = group == "Secrets & PII" and clean
        body = []
        for c in sorted(checks,
                        key=lambda x: {"error": 0, "warn": 1, "ok": 2}[x.level]):
            if secrets_summary:
                continue
            if c.level == "ok" and not show_ok:
                continue
            loc = (" (line %d)" % c.line) if c.line else ""
            body.append("  [%s] %s - %s%s" % (
                _SYMBOL[c.level], c.category, c.message, loc))
        if secrets_summary:
            body.append("  [PASS] no secrets or unredacted PII detected")
        if not body:
            # Nothing to show (e.g. --quiet on an all-clean group): skip it.
            continue
        lines.append(group)
        lines.extend(body)
        lines.append("")

    n_err, n_warn = len(result.errors), len(result.warnings)
    verdict = "PASS" if result.ok(strict) else "FAIL"
    tail = " (--strict: warnings fail the gate)" if strict else ""
    lines.append("Result: %s - %d error(s), %d warning(s)%s" % (
        verdict, n_err, n_warn, tail))
    return "\n".join(lines)
