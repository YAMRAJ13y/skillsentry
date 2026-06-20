"""SkillSentry command-line interface.

    skillsentry scan <path> [--json] [--llm] [--fail-on high|medium|low|never]
    skillsentry version
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .detector import scan
from .models import SEVERITY_RANK
from .report import to_dict, to_markdown

_FAIL_THRESHOLD = {"high": 3, "medium": 2, "low": 1, "never": 99}


def _run_scan(path: str, as_json: bool, use_llm: bool, fail_on: str) -> int:
    report = scan(path, use_llm=use_llm)
    if as_json:
        print(json.dumps(to_dict(report), indent=2, ensure_ascii=False))
    else:
        print(to_markdown(report))

    worst = max([SEVERITY_RANK[f.severity] for f in report.findings] + [0])
    if report.rug_pull.mutated:
        worst = max(worst, SEVERITY_RANK["high"])
    return 1 if worst >= _FAIL_THRESHOLD[fail_on] else 0


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        prog="skillsentry",
        description="Scan MCP servers and agent skills for prompt-injection, "
        "tool-poisoning, and excessive agency.",
    )
    sub = parser.add_subparsers(dest="cmd")

    scan_p = sub.add_parser("scan", help="scan an MCP tool/config or a skill")
    scan_p.add_argument("path", help="path to a .json tool/config or a SKILL.md")
    scan_p.add_argument("--json", action="store_true", help="emit JSON instead of markdown")
    scan_p.add_argument("--llm", action="store_true", help="enable the optional Claude classifier")
    scan_p.add_argument(
        "--fail-on",
        choices=list(_FAIL_THRESHOLD),
        default="high",
        help="exit non-zero when a finding at/above this severity exists (default: high)",
    )

    sub.add_parser("version", help="print the version")

    args = parser.parse_args(argv)

    if args.cmd == "scan":
        return _run_scan(args.path, args.json, args.llm, args.fail_on)
    if args.cmd == "version":
        print(__version__)
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
