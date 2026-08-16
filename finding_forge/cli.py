"""Command-line interface for finding-forge.

Subcommands:
    new    Scaffold a report from a bug-class template.
    cvss   Score / build a CVSS v3.1 vector.
    lint   Gate a drafted report on completeness + leaked secrets.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__, cvss, lint, templates


# --------------------------------------------------------------------------
# new
# --------------------------------------------------------------------------

def _cmd_new(args):
    try:
        report = templates.render(args.type, title=args.title)
    except KeyError:
        print("error: unknown bug class %r" % args.type, file=sys.stderr)
        return 2

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(report)
        except OSError as exc:
            print("error: could not write %s: %s" % (args.output, exc),
                  file=sys.stderr)
            return 2
        print("wrote %s (%s template)" % (args.output, args.type),
              file=sys.stderr)
        print("next: fill every <TODO>, then run `finding-forge lint %s`"
              % args.output, file=sys.stderr)
    else:
        sys.stdout.write(report)
    return 0


# --------------------------------------------------------------------------
# cvss
# --------------------------------------------------------------------------

_FLAG_TO_METRIC = [
    ("av", "AV"), ("ac", "AC"), ("pr", "PR"), ("ui", "UI"),
    ("s", "S"), ("c", "C"), ("i", "I"), ("a", "A"),
]


def _cmd_cvss(args):
    flags = {metric: getattr(args, flag) for flag, metric in _FLAG_TO_METRIC}
    any_flag = any(v is not None for v in flags.values())

    try:
        if args.vector:
            if any_flag:
                print("error: pass a vector OR --av/--ac/... flags, not both",
                      file=sys.stderr)
                return 2
            metrics = cvss.parse_vector(args.vector)
        elif any_flag:
            missing = [m for m, v in flags.items() if v is None]
            if missing:
                print("error: missing metric flag(s): %s"
                      % ", ".join("--" + m.lower() for m in missing),
                      file=sys.stderr)
                return 2
            metrics = cvss.parse_vector(cvss.build_vector(flags))
        else:
            print("error: provide a CVSS vector or the --av/--ac/... flags",
                  file=sys.stderr)
            return 2
    except cvss.CVSSError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    vector = cvss.format_vector(metrics)
    score = cvss.base_score(metrics)
    rating = cvss.severity(score)

    if args.json:
        print(json.dumps({
            "vector": vector,
            "base_score": score,
            "severity": rating,
            "metrics": {k: metrics[k] for k in cvss.METRIC_ORDER},
        }, indent=2))
        return 0

    print("Vector      : %s" % vector)
    print("Base score  : %.1f" % score)
    print("Severity    : %s" % rating)
    if args.explain:
        print("Metrics     :")
        for name, value in cvss.describe(metrics):
            print("  - %-22s %s" % (name + ":", value))
    return 0


# --------------------------------------------------------------------------
# lint
# --------------------------------------------------------------------------

def _cmd_lint(args):
    try:
        result = lint.lint_file(args.report)
    except OSError as exc:
        print("error: could not read %s: %s" % (args.report, exc),
              file=sys.stderr)
        return 2

    if args.json:
        payload = {
            "source": args.report,
            "ok": result.ok(args.strict),
            "errors": len(result.errors),
            "warnings": len(result.warnings),
            "checks": [c._asdict() for c in result.checks],
        }
        print(json.dumps(payload, indent=2))
    else:
        print(lint.format_report(result, source=args.report,
                                 strict=args.strict, show_ok=not args.quiet))
    return result.exit_code(args.strict)


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="finding-forge",
        description="Forge a verified finding into a clean, submission-ready "
                    "vulnerability report with accurate CVSS 3.1 scoring and a "
                    "pre-submit secret/completeness lint.",
        epilog="One clean, reproducible report beats ten noisy ones.",
    )
    parser.add_argument("-V", "--version", action="version",
                        version="finding-forge %s" % __version__)
    sub = parser.add_subparsers(dest="command", metavar="{new,cvss,lint}")
    sub.required = True

    p_new = sub.add_parser(
        "new", help="scaffold a report from a bug-class template")
    p_new.add_argument("--type", required=True, choices=templates.CLASS_ORDER,
                       metavar="CLASS",
                       help="bug class: " + ", ".join(templates.CLASS_ORDER))
    p_new.add_argument("--title", help="report title (overrides the hint)")
    p_new.add_argument("-o", "--output", metavar="FILE",
                       help="write to FILE instead of stdout")
    p_new.set_defaults(func=_cmd_new)

    p_cvss = sub.add_parser(
        "cvss", help="score or build a CVSS v3.1 vector")
    p_cvss.add_argument("vector", nargs="?",
                        help="a CVSS v3.1 vector, e.g. "
                             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    for flag, metric in _FLAG_TO_METRIC:
        p_cvss.add_argument("--" + flag, choices=cvss.METRICS[metric],
                            metavar=metric,
                            help="%s (%s)" % (cvss.METRIC_NAMES[metric],
                                              "/".join(cvss.METRICS[metric])))
    p_cvss.add_argument("--explain", action="store_true",
                        help="print the expanded metric names")
    p_cvss.add_argument("--json", action="store_true",
                        help="emit machine-readable JSON")
    p_cvss.set_defaults(func=_cmd_cvss)

    p_lint = sub.add_parser(
        "lint", help="check a drafted report (pre-submit gate)")
    p_lint.add_argument("report", help="path to the Markdown report")
    p_lint.add_argument("--strict", action="store_true",
                        help="treat warnings as failures (recommended for CI)")
    p_lint.add_argument("--quiet", action="store_true",
                        help="hide passing checks, show only problems")
    p_lint.add_argument("--json", action="store_true",
                        help="emit machine-readable JSON")
    p_lint.set_defaults(func=_cmd_lint)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
