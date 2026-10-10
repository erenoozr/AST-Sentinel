"""Quality rules: cyclomatic complexity and dead code."""
from __future__ import annotations

import ast
from typing import Iterable, Iterator

from ..core import BaseRule, Finding, FunctionMetric, Severity

COMPLEXITY_THRESHOLD = 10

_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef)
_SCOPES = (*_DEFS, ast.ClassDef)
_BRANCHES = (ast.If, ast.IfExp, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler)


def _walk_own(nodes: Iterable[ast.AST]) -> Iterator[ast.AST]:
    """Walk the nodes and their subtrees without descending into nested function/class bodies."""
    stack = list(nodes)
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, _SCOPES):
            stack.extend(ast.iter_child_nodes(node))


def cyclomatic_complexity(func: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """McCabe: 1 + decision points (if/elif, loops, except, case, and/or, comprehension conditions)."""
    score = 1
    for node in _walk_own(func.body):
        if isinstance(node, _BRANCHES):
            score += 1
        elif isinstance(node, ast.BoolOp):
            score += len(node.values) - 1
        elif isinstance(node, ast.comprehension):
            score += 1 + len(node.ifs)
        elif isinstance(node, ast.match_case):
            # `case _:` / `case x:` match everything, like `else`; they add no new branch.
            if not (isinstance(node.pattern, ast.MatchAs) and node.pattern.pattern is None):
                score += 1
    return score


class ComplexityRule(BaseRule):
    rule_id = "CMP001"
    title = "High cyclomatic complexity"
    severity = Severity.MEDIUM
    description = f"Functions whose cyclomatic complexity exceeds {COMPLEXITY_THRESHOLD}."
    node_types = _DEFS

    def check(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> Iterator[Finding]:
        score = cyclomatic_complexity(node)
        self.ctx.metrics.append(FunctionMetric(".".join([*self.ctx.scope, node.name]), node.lineno, score))
        if score > COMPLEXITY_THRESHOLD:
            yield self.finding(
                node,
                f"Function '{node.name}' has a cyclomatic complexity of {score} (threshold: {COMPLEXITY_THRESHOLD}).",
                "Split the function into single-purpose helpers; flatten nested conditions with early returns "
                "(guard clauses); replace long if/elif chains with dict-based dispatch.",
            )


def _stored_names(targets: Iterable[ast.AST]) -> Iterator[ast.Name]:
    for target in targets:
        for node in ast.walk(target):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                yield node


class UnusedLocalRule(BaseRule):
    rule_id = "DC001"
    title = "Unused local variable"
    severity = Severity.LOW
    description = "Local variables that are assigned inside a function but never read."
    node_types = _DEFS

    def check(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> Iterator[Finding]:
        loads: set[str] = set()
        declared: set[str] = set()
        for sub in ast.walk(node):  # reads inside nested functions count too (closures)
            if isinstance(sub, ast.Name) and not isinstance(sub.ctx, ast.Store):
                loads.add(sub.id)
            elif isinstance(sub, ast.AugAssign) and isinstance(sub.target, ast.Name):
                loads.add(sub.target.id)  # `x += 1` reads x
            elif isinstance(sub, (ast.Global, ast.Nonlocal)):
                declared.update(sub.names)
            elif isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and sub.func.id in {"locals", "vars"}:
                return  # variables are accessed dynamically; no reliable verdict possible

        stored: list[ast.Name] = []
        for sub in _walk_own(node.body):
            if isinstance(sub, ast.Assign):
                stored.extend(_stored_names(sub.targets))
            elif isinstance(sub, ast.AnnAssign) and sub.value is not None:
                stored.extend(_stored_names([sub.target]))
            elif isinstance(sub, ast.NamedExpr):
                stored.extend(_stored_names([sub.target]))

        first_store: dict[str, ast.Name] = {}
        for name in sorted(stored, key=lambda n: (n.lineno, n.col_offset)):
            first_store.setdefault(name.id, name)
        for name_id, name in first_store.items():
            if name_id in loads or name_id in declared or name_id.startswith("_"):
                continue
            yield self.finding(
                name,
                f"Variable '{name_id}' is assigned in '{node.name}' but never read.",
                f"Remove the '{name_id}' assignment; if the expression has side effects keep only the expression, "
                f"or name the variable '_' to mark it as intentionally ignored.",
            )


def _is_private(name: str) -> bool:
    return name.startswith("_") and not (name.startswith("__") and name.endswith("__"))


class UnusedPrivateFunctionRule(BaseRule):
    rule_id = "DC002"
    title = "Unused private function"
    severity = Severity.LOW
    description = "_private functions and methods that are never referenced within the file."
    node_types = (ast.Module,)

    def check(self, node: ast.Module) -> Iterator[Finding]:
        used: set[str] = set()
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and not isinstance(sub.ctx, ast.Store):
                used.add(sub.id)
            elif isinstance(sub, ast.Attribute):
                used.add(sub.attr)
            elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                used.add(sub.value)  # string references such as getattr(obj, "_x") and __all__
        for sub in ast.walk(node):
            # Decorated functions (routes, properties, registries...) are called indirectly; skip them.
            if isinstance(sub, _DEFS) and _is_private(sub.name) and not sub.decorator_list and sub.name not in used:
                yield self.finding(
                    sub,
                    f"Private function '{sub.name}' is defined but never used in this file.",
                    f"Delete '{sub.name}'; if other modules use it, drop the leading '_' and make it part of the "
                    f"public API.",
                )
