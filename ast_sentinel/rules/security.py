"""Security rules: hardcoded secrets, dangerous calls, SQL injection, weak cryptography."""
from __future__ import annotations

import ast
import math
import re
from collections import Counter
from typing import Iterator

from ..core import BaseRule, Finding, ScanContext, Severity

# --- SEC001: hardcoded secrets ----------------------------------------------------------

_SECRET_NAME = re.compile(
    r"(?:^|_)(?:password|passwd|passphrase|pwd|secret|token|api_?key|apikey|access_?key|"
    r"secret_?key|private_?key|client_?secret|credentials?|auth_?token)(?:_|$)"
)
_PLACEHOLDER = re.compile(
    r"^(?:\*+|x+|<[^>]*>|\$\{[^}]*\}|\{\{.*\}\}|changeme|change_me|example|dummy|none|null|placeholder|your[_-].*)$",
    re.IGNORECASE,
)
_KNOWN_SECRETS = {
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}"),
    "AWS Access Key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "GitHub Token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "Slack Token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    "Stripe Secret Key": re.compile(r"\b[sr]k_live_[A-Za-z0-9]{24,}\b"),
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "PEM private key": re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
}
_TOKEN_CHARS = re.compile(r"[A-Za-z0-9+/=_\-]+")
_HEX = re.compile(r"[0-9a-fA-F]+")
_SECRET_FIX = (
    "Remove the secret from source code and load it at runtime from os.environ, an untracked .env "
    "file or a secret manager (Vault, AWS Secrets Manager). Revoke and rotate any key that has "
    "already been committed."
)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in Counter(text).values())


def known_secret_kind(text: str) -> str | None:
    return next((kind for kind, rx in _KNOWN_SECRETS.items() if rx.search(text)), None)


def is_high_entropy_token(text: str) -> bool:
    """Random-looking strings without whitespace, containing letters and digits, in a base64/hex alphabet."""
    if len(text) < 20 or not _TOKEN_CHARS.fullmatch(text):
        return False
    if not (re.search(r"\d", text) and re.search(r"[A-Za-z]", text)):
        return False
    if _HEX.fullmatch(text):  # hex has 16 symbols: entropy caps at 4 bits/char
        return len(text) >= 32 and shannon_entropy(text) >= 3.0
    return shannon_entropy(text) >= 4.0


def _snake(name: str) -> str:
    name = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()
    return re.sub(r"[^a-z0-9]+", "_", name).strip("_")


def _target_name(target: ast.AST) -> str | None:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str):
        return target.slice.value
    return None


def _named_values(node: ast.AST) -> Iterator[tuple[str, ast.AST]]:
    """Yield values bound to a name: assignments, keyword arguments, dict entries, parameter defaults."""
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if name := _target_name(target):
                yield name, node.value
    elif isinstance(node, ast.AnnAssign) and node.value is not None:
        if name := _target_name(node.target):
            yield name, node.value
    elif isinstance(node, ast.keyword) and node.arg:
        yield node.arg, node.value
    elif isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values):
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                yield key.value, value
    elif isinstance(node, ast.arguments):
        positional = [*node.posonlyargs, *node.args]
        for arg, default in zip(positional[len(positional) - len(node.defaults):], node.defaults):
            yield arg.arg, default
        for arg, default in zip(node.kwonlyargs, node.kw_defaults):
            if default is not None:
                yield arg.arg, default


class HardcodedSecretRule(BaseRule):
    rule_id = "SEC001"
    title = "Hardcoded secret"
    severity = Severity.HIGH
    description = "Password/API key variables, JWT and known token patterns, high-entropy string literals."
    node_types = (ast.Assign, ast.AnnAssign, ast.keyword, ast.Dict, ast.arguments, ast.Constant)

    def __init__(self, ctx: ScanContext) -> None:
        super().__init__(ctx)
        # Literals already reported by name; the parent node is visited first, so they are not reported twice.
        self._reported: set[int] = set()

    def check(self, node: ast.AST) -> Iterator[Finding]:
        if isinstance(node, ast.Constant):
            yield from self._check_literal(node)
            return
        for name, value in _named_values(node):
            if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
                continue
            secret = value.value
            if not _SECRET_NAME.search(_snake(name)) or len(secret) < 4 or _PLACEHOLDER.match(secret):
                continue
            if len(secret.split()) > 5:  # a sentence (message/help text); passphrases are usually shorter
                continue
            self._reported.add(id(value))
            kind = known_secret_kind(secret)
            suffix = f" ({kind} pattern)" if kind else ""
            yield self.finding(
                value,
                f"A hardcoded secret is assigned to '{name}'{suffix}.",
                f"{_SECRET_FIX} Example: {name} = os.environ[\"{_snake(name).upper()}\"]",
                severity=Severity.CRITICAL if kind else Severity.HIGH,
                redact=secret,
            )

    def _check_literal(self, node: ast.Constant) -> Iterator[Finding]:
        if id(node) in self._reported or not isinstance(node.value, str):
            return
        text = node.value
        if kind := known_secret_kind(text):
            yield self.finding(node, f"String literal matches the {kind} credential pattern.",
                               _SECRET_FIX, severity=Severity.CRITICAL, redact=text)
        elif is_high_entropy_token(text):
            yield self.finding(
                node,
                f"High-entropy (≈{shannon_entropy(text):.2f} bits/char) token-like string literal.",
                _SECRET_FIX + " If the value is not secret (e.g. a fixed identifier), this finding can be ignored.",
                severity=Severity.MEDIUM,
                redact=text,
            )


# --- SEC002: dangerous functions --------------------------------------------------------

_SHELL_FIX = ("Call subprocess.run([\"command\", arg1, arg2], shell=False, check=True) with an argument list "
              "and validate user input against an allowlist.")
_PICKLE_FIX = ("Use a format that cannot execute code, such as json, for untrusted data; if pickle is "
               "unavoidable, sign the payload with hmac and verify the signature before loading.")
_DANGEROUS_CALLS: dict[str, tuple[Severity, str, str]] = {
    "eval": (Severity.CRITICAL,
             "evaluates its argument as Python code; external input leads to remote code execution (RCE).",
             "To parse data use ast.literal_eval() or json.loads(); for dynamic behaviour dispatch through a "
             "dict of allowed operations."),
    "exec": (Severity.CRITICAL,
             "executes arbitrary Python code; external input leads to remote code execution (RCE).",
             "Replace exec() with explicitly defined functions or a plugin interface; executed code must never "
             "be derived from external input."),
    "os.system": (Severity.HIGH, "runs the command through a shell; concatenated input enables command injection.",
                  _SHELL_FIX),
    "os.popen": (Severity.HIGH, "runs the command through a shell; concatenated input enables command injection.",
                 _SHELL_FIX),
    "pickle.loads": (Severity.HIGH, "can execute arbitrary code when loading untrusted data (__reduce__).", _PICKLE_FIX),
    "pickle.load": (Severity.HIGH, "can execute arbitrary code when loading untrusted data (__reduce__).", _PICKLE_FIX),
}


class DangerousCallRule(BaseRule):
    rule_id = "SEC002"
    title = "Dangerous function call"
    severity = Severity.HIGH
    description = "eval(), exec(), os.system(), pickle.loads() and similar code/command execution calls."
    node_types = (ast.Call,)

    def check(self, node: ast.Call) -> Iterator[Finding]:
        name = self.ctx.resolve(node.func)
        if name in _DANGEROUS_CALLS:
            severity, why, fix = _DANGEROUS_CALLS[name]
            yield self.finding(node, f"{name}() {why}", fix, severity=severity)


# --- SEC003: SQL injection --------------------------------------------------------------

_SQL_METHODS = {"execute", "executemany", "executescript"}


def _is_str_expr(node: ast.AST) -> bool:
    return isinstance(node, ast.JoinedStr) or (isinstance(node, ast.Constant) and isinstance(node.value, str))


def _flatten_add(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _flatten_add(node.left) + _flatten_add(node.right)
    return [node]


class SQLInjectionRule(BaseRule):
    rule_id = "SEC003"
    title = "SQL injection risk"
    severity = Severity.CRITICAL
    description = "cursor.execute() queries built dynamically with f-strings, % or +."
    node_types = (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Call)

    def __init__(self, ctx: ScanContext) -> None:
        super().__init__(ctx)
        # (scope..., variable) -> how the query got tainted; covers `q = f"..."; cursor.execute(q)`.
        # shortcut: flow-insensitive (branches are not distinguished), switch to real data-flow analysis if false positives grow.
        self._tainted: dict[tuple[str, ...], str] = {}

    def _key(self, name: str) -> tuple[str, ...]:
        return (*self.ctx.scope, name)

    def _unsafe(self, expr: ast.AST) -> str | None:
        if isinstance(expr, ast.JoinedStr) and any(isinstance(v, ast.FormattedValue) for v in expr.values):
            return "an f-string"
        if isinstance(expr, ast.BinOp):
            if isinstance(expr.op, ast.Mod) and _is_str_expr(expr.left) and not isinstance(expr.right, ast.Constant):
                return "% formatting"
            if isinstance(expr.op, ast.Add):
                parts = _flatten_add(expr)
                if any(_is_str_expr(p) for p in parts) and not all(isinstance(p, ast.Constant) for p in parts):
                    return "+ concatenation"
        if isinstance(expr, ast.Name):
            return self._tainted.get(self._key(expr.id))
        return None

    def check(self, node: ast.AST) -> Iterator[Finding]:
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr in _SQL_METHODS and node.args:
                if how := self._unsafe(node.args[0]):
                    yield self.finding(
                        node,
                        f"The SQL query is built dynamically with {how}; input is embedded directly in the query text.",
                        "Use a parameterized query: cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,)). "
                        "The placeholder is ? (sqlite3) or %s (psycopg/PyMySQL) depending on the driver; pick "
                        "dynamic table/column names from an allowlist.",
                    )
            return
        if isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name) and isinstance(node.op, ast.Add) and not isinstance(node.value, ast.Constant):
                self._tainted[self._key(node.target.id)] = "+= concatenation"
            return
        if node.value is None:
            return
        how = self._unsafe(node.value)
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                if how:
                    self._tainted[self._key(target.id)] = how
                else:
                    self._tainted.pop(self._key(target.id), None)


# --- SEC004: weak cryptography ----------------------------------------------------------

_WEAK_HASHES = {"md5", "sha1"}


class WeakCryptoRule(BaseRule):
    rule_id = "SEC004"
    title = "Weak cryptographic hash"
    severity = Severity.MEDIUM
    description = "Use of hashlib.md5() / hashlib.sha1() (and hashlib.new('md5'|'sha1'))."
    node_types = (ast.Call,)

    def check(self, node: ast.Call) -> Iterator[Finding]:
        name = self.ctx.resolve(node.func)
        algo = None
        if name in {"hashlib.md5", "hashlib.sha1"}:
            algo = name.split(".")[1]
        elif name == "hashlib.new" and node.args and isinstance(node.args[0], ast.Constant):
            candidate = str(node.args[0].value).lower()
            algo = candidate if candidate in _WEAK_HASHES else None
        if algo is None:
            return
        not_for_security = any(
            kw.arg == "usedforsecurity" and isinstance(kw.value, ast.Constant) and kw.value.value is False
            for kw in node.keywords
        )
        if not_for_security:
            return
        yield self.finding(
            node,
            f"{algo.upper()} is cryptographically broken (collision attacks) and must not be used for security.",
            "Use hashlib.sha256() or hashlib.sha3_256() for integrity/signatures; for password storage use "
            "hashlib.scrypt() or hashlib.pbkdf2_hmac('sha256', password, salt, 600_000). For non-security "
            "checksums pass usedforsecurity=False.",
        )
