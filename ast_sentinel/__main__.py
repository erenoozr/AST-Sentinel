"""Command line: python -m ast_sentinel <file|dir>... [--json [FILE]] [--color auto|always|never]"""
from __future__ import annotations

import argparse
import sys

from .core import SecurityScanner
from .report import JsonExporter, TerminalReporter, enable_ansi


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ast_sentinel", description="Static code security and complexity analyzer")
    parser.add_argument("paths", nargs="+", help="Python files or directories to scan")
    parser.add_argument("--json", nargs="?", const="security_report.json", metavar="FILE",
                        help="Export results as JSON (default: security_report.json)")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto", help="Colored output")
    args = parser.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8")  # needed for the box-drawing characters
    except (AttributeError, ValueError):
        pass
    ansi = enable_ansi()
    color = ansi if args.color == "auto" else args.color == "always"

    results = SecurityScanner().scan_paths(args.paths)
    print(TerminalReporter(color=color).render(results))
    if args.json:
        print(f"\nJSON report: {JsonExporter(args.json).export(results).resolve()}")
    return 1 if any(r.findings or r.error for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
