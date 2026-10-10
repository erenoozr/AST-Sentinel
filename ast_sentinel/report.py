"""Colored, framed terminal reporter and JSON exporter."""
from __future__ import annotations

import json
import os
import shutil
import sys
import textwrap
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from . import __version__
from .core import Finding, ScanResult, Severity
from .rules.quality import COMPLEXITY_THRESHOLD

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[1;32m"
SEVERITY_STYLE = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[1;36m",
}


def enable_ansi(stream: TextIO = sys.stdout) -> bool:
    """Enable ANSI colors when the stream is a terminal (turns on VT mode in the Windows console)."""
    if os.environ.get("NO_COLOR") or not stream.isatty():
        return False
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except (AttributeError, OSError):
        return False


def _fit(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


class TerminalReporter:
    def __init__(self, color: bool = False, width: int | None = None) -> None:
        self.color = color
        self.width = width or max(60, min(120, shutil.get_terminal_size((100, 24)).columns))

    def _c(self, text: str, style: str | None) -> str:
        return f"{style}{text}{RESET}" if self.color and style else text

    def render(self, results: list[ScanResult]) -> str:
        out = [self._banner()]
        for result in results:
            if result.error:
                out.append(self._c(f"✖ {result.file}: {result.error}", SEVERITY_STYLE[Severity.HIGH]))
            out.extend(self._box(f) for f in result.findings)
        out.append(self._summary(results))
        return "\n".join(out)

    def _banner(self) -> str:
        inner = self.width - 2
        title = f"AST-Sentinel v{__version__} · Static Code Security & Complexity Analyzer"
        return "\n".join([
            "╔" + "═" * inner + "╗",
            "║" + self._c(_fit(title, inner).center(inner), BOLD) + "║",
            "╚" + "═" * inner + "╝",
        ])

    def _box(self, f: Finding) -> str:
        inner = self.width - 4
        label = f" {f.severity.name} "
        head = _fit(f" {f.rule_id} · {f.title} ", self.width - 4 - len(label))
        fill = self.width - 3 - len(label) - len(head)
        lines = ["╭─" + self._c(label, SEVERITY_STYLE[f.severity]) + self._c(head, BOLD) + "─" * fill + "╮"]

        rows: list[tuple[str, str | None]] = [(f"Location : {f.file}:{f.line}:{f.col}", DIM), ("", None)]
        for offset, code in enumerate(f.snippet.splitlines()):
            marker = "▶" if offset == 0 else " "
            rows.append((_fit(f"{marker}{f.line + offset:>5} │ {code.expandtabs(4).rstrip()}", inner),
                         SEVERITY_STYLE[f.severity] if offset == 0 and f.severity < Severity.CRITICAL else None))
        rows.append(("", None))
        for prefix, text, style in (("Issue : ", f.message, None), ("Fix   : ", f.fix, GREEN)):
            wrapped = textwrap.wrap(text, inner, initial_indent=prefix, subsequent_indent=" " * len(prefix))
            rows.extend((line, style) for line in wrapped)

        lines.extend("│ " + self._c(text.ljust(inner), style) + " │" for text, style in rows)
        lines.append("╰" + "─" * (self.width - 2) + "╯")
        return "\n".join(lines)

    def _summary(self, results: list[ScanResult]) -> str:
        findings = [f for r in results for f in r.findings]
        errors = sum(1 for r in results if r.error)
        counts = Counter(f.severity for f in findings)
        lines = [
            "",
            self._c("═" * self.width, BOLD),
            self._c(" SUMMARY", BOLD),
            self._c("═" * self.width, BOLD),
            f" Files scanned: {len(results)}    Total findings: {len(findings)}    Unreadable files: {errors}",
            " " + "   ".join(
                self._c(f" {s.name} ", SEVERITY_STYLE[s]) + f" {counts.get(s, 0)}" for s in sorted(Severity, reverse=True)
            ),
        ]
        by_rule = Counter((f.rule_id, f.title) for f in findings)
        if by_rule:
            lines += ["", " Findings by rule:"]
            lines += [f"   {rid:<7} {title:<34} ×{n}" for (rid, title), n in sorted(by_rule.items())]

        metrics = sorted(((r.file, m) for r in results for m in r.metrics), key=lambda x: -x[1].complexity)[:10]
        if metrics:
            lines += ["", f" Most complex functions (cyclomatic complexity, threshold {COMPLEXITY_THRESHOLD}):"]
            for file, m in metrics:
                row = f"   {m.complexity:>4}  {m.name}  ({Path(file).name}:{m.line})"
                lines.append(self._c(row + "  ⚠ above threshold", SEVERITY_STYLE[Severity.HIGH])
                             if m.complexity > COMPLEXITY_THRESHOLD else row)

        lines.append("")
        if findings or errors:
            lines.append(self._c(f" ✖ {len(findings)} finding(s) reported.", SEVERITY_STYLE[Severity.HIGH]))
        else:
            lines.append(self._c(" ✔ No issues found.", GREEN))
        return "\n".join(lines)


class JsonExporter:
    def __init__(self, path: str | Path = "security_report.json") -> None:
        self.path = Path(path)

    def export(self, results: list[ScanResult]) -> Path:
        findings = [f for r in results for f in r.findings]
        report = {
            "tool": "AST-Sentinel",
            "version": __version__,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "summary": {
                "files": len(results),
                "errors": sum(1 for r in results if r.error),
                "findings": len(findings),
                "by_severity": {s.name: sum(f.severity == s for f in findings) for s in sorted(Severity, reverse=True)},
            },
            "results": [r.to_dict() for r in results],
        }
        self.path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        return self.path
