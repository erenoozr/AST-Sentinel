"""AST-Sentinel core: finding model, rule interface (BaseRule) and the AST scanner."""
from __future__ import annotations

import ast
import tokenize
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import ClassVar, Iterable, Iterator

_SKIP_DIRS = {"__pycache__", "venv", "node_modules", "site-packages"}
_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    title: str
    message: str
    fix: str
    file: str
    line: int
    col: int
    snippet: str

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.name
        return data


@dataclass(frozen=True)
class FunctionMetric:
    name: str
    line: int
    complexity: int


@dataclass
class ScanResult:
    file: str
    findings: list[Finding] = field(default_factory=list)
    metrics: list[FunctionMetric] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
            "metrics": [asdict(m) for m in self.metrics],
        }


class ScanContext:
    """State shared by all rules while a single file is being scanned."""

    def __init__(self, filename: str, source: str, tree: ast.Module) -> None:
        self.filename = filename
        self.lines = source.splitlines()
        self.tree = tree
        self.scope: list[str] = []  # names of the enclosing functions/classes
        self.metrics: list[FunctionMetric] = []
        self.aliases = self._collect_aliases(tree)

    @staticmethod
    def _collect_aliases(tree: ast.AST) -> dict[str, str]:
        aliases: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        aliases[alias.asname] = alias.name
                    else:
                        top = alias.name.split(".")[0]
                        aliases[top] = top
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                for alias in node.names:
                    aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        return aliases

    def resolve(self, expr: ast.AST) -> str | None:
        """Resolve aliases such as `h.md5` or `from os import system` to a fully dotted name."""
        if isinstance(expr, ast.Name):
            name = self.aliases.get(expr.id, expr.id)
        elif isinstance(expr, ast.Attribute):
            base = self.resolve(expr.value)
            if base is None:
                return None
            name = f"{base}.{expr.attr}"
        else:
            return None
        return name.removeprefix("builtins.")

    def snippet(self, node: ast.AST, max_lines: int = 3) -> str:
        start = node.lineno
        end = min(getattr(node, "end_lineno", None) or start, start + max_lines - 1)
        return "\n".join(self.lines[start - 1:end])


class BaseRule(ABC):
    """Interface for all rules. Subclasses define the class attributes and the `check` method."""

    rule_id: ClassVar[str]
    title: ClassVar[str]
    severity: ClassVar[Severity]
    description: ClassVar[str]
    node_types: ClassVar[tuple[type[ast.AST], ...]]

    def __init__(self, ctx: ScanContext) -> None:
        self.ctx = ctx

    @abstractmethod
    def check(self, node: ast.AST) -> Iterator[Finding]:
        """Called for every node in `node_types`, in pre-order traversal."""

    def finding(
        self,
        node: ast.AST,
        message: str,
        fix: str,
        severity: Severity | None = None,
        redact: str | None = None,
    ) -> Finding:
        snippet = self.ctx.snippet(node)
        if redact:
            # Keep the report itself from leaking the secret.
            masked = redact[:4] + "*" * 8
            snippet = snippet.replace(redact, masked) if redact in snippet else f"<secret value masked: {masked}>"
        return Finding(
            rule_id=self.rule_id,
            severity=severity or self.severity,
            title=self.title,
            message=message,
            fix=fix,
            file=self.ctx.filename,
            line=node.lineno,
            col=node.col_offset + 1,
            snippet=snippet,
        )


class SecurityScanner(ast.NodeVisitor):
    """Walks the AST once and dispatches every node to the rules interested in it."""

    def __init__(self, rules: Iterable[type[BaseRule]] | None = None) -> None:
        if rules is None:
            from .rules import DEFAULT_RULES  # lazy import avoids a circular import

            rules = DEFAULT_RULES
        self.rule_classes = tuple(rules)
        self._ctx: ScanContext | None = None
        self._dispatch: dict[type[ast.AST], list[BaseRule]] = {}
        self._findings: list[Finding] = []

    def scan_source(self, source: str, filename: str = "<string>") -> ScanResult:
        try:
            tree = ast.parse(source, filename=filename)
        except SyntaxError as exc:
            return ScanResult(filename, error=f"Syntax error (line {exc.lineno}): {exc.msg}")
        except ValueError as exc:
            return ScanResult(filename, error=f"Could not parse: {exc}")

        self._ctx = ctx = ScanContext(filename, source, tree)
        self._findings = []
        self._dispatch = {}
        for rule_cls in self.rule_classes:
            rule = rule_cls(ctx)
            for node_type in rule_cls.node_types:
                self._dispatch.setdefault(node_type, []).append(rule)

        try:
            self.visit(tree)
        except RecursionError:
            return ScanResult(filename, error="AST is nested too deeply; scan aborted.")

        unique = {(f.rule_id, f.line, f.col, f.message): f for f in self._findings}
        findings = sorted(unique.values(), key=lambda f: (f.line, f.col, -f.severity))
        return ScanResult(filename, findings, ctx.metrics)

    def scan_file(self, path: str | Path) -> ScanResult:
        path = Path(path)
        try:
            with tokenize.open(path) as fh:  # honours PEP 263 encoding declarations
                source = fh.read()
        except (OSError, SyntaxError, UnicodeDecodeError) as exc:
            return ScanResult(str(path), error=f"Could not read: {exc}")
        return self.scan_source(source, str(path))

    def scan_paths(self, paths: Iterable[str | Path]) -> list[ScanResult]:
        results: list[ScanResult] = []
        for root in map(Path, paths):
            if root.is_dir():
                files = sorted(
                    f for f in root.rglob("*.py")
                    if not any(p.startswith(".") or p in _SKIP_DIRS for p in f.relative_to(root).parts)
                )
            else:
                files = [root]
            results.extend(self.scan_file(f) for f in files)
        return results

    def generic_visit(self, node: ast.AST) -> None:
        for rule in self._dispatch.get(type(node), ()):
            self._findings.extend(rule.check(node))
        scoped = isinstance(node, _SCOPE_NODES)
        if scoped:
            self._ctx.scope.append(node.name)
        try:
            super().generic_visit(node)
        finally:
            if scoped:
                self._ctx.scope.pop()
