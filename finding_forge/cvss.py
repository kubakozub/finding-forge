"""Accurate CVSS v3.1 base-score implementation (standard library only).

The equations follow the FIRST *CVSS v3.1 Specification*, section 7.1
(Base Metrics Equations) and Appendix A (the ``Roundup`` function).  Every
number here is verified against the official FIRST calculator for the
canonical vectors exercised in ``tests/test_cvss.py`` — do not "simplify"
the Roundup or the scope-changed impact term; they are deliberately exact.
"""

from __future__ import annotations

import math

# --------------------------------------------------------------------------
# Metric weights (CVSS v3.1 spec, Table in section 7.4)
# --------------------------------------------------------------------------

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
# Privileges Required weights depend on Scope.
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}

# Allowed values per base metric (order is significant for `choices`/help).
METRICS = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "R"),
    "S": ("U", "C"),
    "C": ("H", "L", "N"),
    "I": ("H", "L", "N"),
    "A": ("H", "L", "N"),
}
# Canonical ordering of a base vector.
METRIC_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

METRIC_NAMES = {
    "AV": "Attack Vector",
    "AC": "Attack Complexity",
    "PR": "Privileges Required",
    "UI": "User Interaction",
    "S": "Scope",
    "C": "Confidentiality",
    "I": "Integrity",
    "A": "Availability",
}

VALUE_NAMES = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S": {"U": "Unchanged", "C": "Changed"},
    "C": {"H": "High", "L": "Low", "N": "None"},
    "I": {"H": "High", "L": "Low", "N": "None"},
    "A": {"H": "High", "L": "Low", "N": "None"},
}


class CVSSError(ValueError):
    """Raised when a CVSS vector is malformed or has invalid metric values."""


# --------------------------------------------------------------------------
# Parsing / building
# --------------------------------------------------------------------------

def parse_vector(vector):
    """Parse a CVSS v3.1 vector string into a dict of base metrics.

    Accepts an optional ``CVSS:3.1/`` (or ``3.0``) prefix and is
    case-insensitive.  Raises :class:`CVSSError` on any unknown metric,
    illegal value, or missing base metric.
    """
    if not isinstance(vector, str):
        raise CVSSError("vector must be a string")
    text = vector.strip()
    if not text:
        raise CVSSError("empty CVSS vector")

    metrics = {}
    for part in text.split("/"):
        part = part.strip()
        if not part:
            continue
        if ":" not in part:
            raise CVSSError("malformed component: %r" % part)
        key, _, value = part.partition(":")
        key = key.strip().upper()
        value = value.strip().upper()
        if key == "CVSS":
            if value not in ("3.1", "3.0"):
                raise CVSSError("unsupported CVSS version: %s" % value)
            continue
        if key not in METRICS:
            raise CVSSError("unknown metric: %s" % key)
        if value not in METRICS[key]:
            raise CVSSError(
                "invalid value %s for metric %s (allowed: %s)"
                % (value, key, ", ".join(METRICS[key]))
            )
        if key in metrics and metrics[key] != value:
            raise CVSSError("conflicting values for metric %s" % key)
        metrics[key] = value

    missing = [m for m in METRIC_ORDER if m not in metrics]
    if missing:
        raise CVSSError("missing base metric(s): %s" % ", ".join(missing))
    return metrics


def build_vector(components):
    """Build a canonical ``CVSS:3.1/...`` string from a metric->value map.

    Values are case-insensitive.  Raises :class:`CVSSError` for a missing
    or invalid metric.
    """
    metrics = {}
    for key in METRIC_ORDER:
        raw = components.get(key)
        if raw is None:
            raise CVSSError("missing metric: %s" % key)
        value = str(raw).strip().upper()
        if value not in METRICS[key]:
            raise CVSSError(
                "invalid value %s for metric %s (allowed: %s)"
                % (value, key, ", ".join(METRICS[key]))
            )
        metrics[key] = value
    return format_vector(metrics)


def format_vector(metrics):
    """Return the canonical ``CVSS:3.1/...`` string for a metrics dict."""
    body = "/".join("%s:%s" % (k, metrics[k]) for k in METRIC_ORDER)
    return "CVSS:3.1/" + body


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------

def _roundup(value):
    """CVSS v3.1 ``Roundup`` (Appendix A) — matches the FIRST calculator.

    Rounds *up* to one decimal place, but leaves values that are already at
    one decimal untouched.  Implemented on integers scaled by 100000 to
    avoid binary-float drift, exactly as the reference JavaScript does.
    """
    int_input = int(math.floor(value * 100000 + 0.5))
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def base_score(metrics):
    """Compute the CVSS v3.1 base score (0.0-10.0) for a metrics dict.

    ``metrics`` may also be a vector string, which is parsed first.
    """
    if isinstance(metrics, str):
        metrics = parse_vector(metrics)

    scope_changed = metrics["S"] == "C"

    # Impact Sub-Score.
    iss = 1.0 - (
        (1.0 - _CIA[metrics["C"]])
        * (1.0 - _CIA[metrics["I"]])
        * (1.0 - _CIA[metrics["A"]])
    )
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    # Exploitability.
    pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
    exploitability = (
        8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr * _UI[metrics["UI"]]
    )

    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10.0))
    return _roundup(min(impact + exploitability, 10.0))


def severity(score):
    """Map a base score to its qualitative rating (CVSS v3.1 severity scale)."""
    if score <= 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def score_vector(vector):
    """Convenience: parse (if needed), score and rate.

    Returns ``(score, severity, metrics)``.
    """
    metrics = parse_vector(vector) if isinstance(vector, str) else dict(vector)
    s = base_score(metrics)
    return s, severity(s), metrics


def describe(metrics):
    """Return a list of ``(metric_name, value_name)`` for pretty printing."""
    if isinstance(metrics, str):
        metrics = parse_vector(metrics)
    return [(METRIC_NAMES[k], VALUE_NAMES[k][metrics[k]]) for k in METRIC_ORDER]
