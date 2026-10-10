# AST-Sentinel

A static security and complexity analyzer for Python source code, built on the standard library `ast` module. No third-party dependencies — Python 3.10+ only.

AST-Sentinel walks the abstract syntax tree of your code once, dispatches each node to a set of pluggable rules, and prints a colored, framed report with the exact line, the offending code and a concrete fix suggestion for every finding. Results can also be exported as JSON for CI pipelines.

## Features

### Security rules

| ID | Rule | Detects |
|----|------|---------|
| `SEC001` | Hardcoded secrets | Password / API key / token variables, dict keys, keyword args and default parameters assigned to string literals; known credential patterns (JWT, AWS, GitHub, Slack, Stripe, Google API keys, PEM private keys); high-entropy token-like strings |
| `SEC002` | Dangerous calls | `eval()`, `exec()`, `os.system()`, `os.popen()`, `pickle.loads()`, `pickle.load()` |
| `SEC003` | SQL injection risk | `cursor.execute()` / `executemany()` / `executescript()` with queries built via f-strings, `%` formatting or `+` concatenation — including queries built in a variable first (`q = "..." + x; cursor.execute(q)`) |
| `SEC004` | Weak cryptography | `hashlib.md5()`, `hashlib.sha1()`, `hashlib.new("md5"/"sha1")` (skipped when `usedforsecurity=False`) |

### Quality rules

| ID | Rule | Detects |
|----|------|---------|
| `CMP001` | Cyclomatic complexity | Functions scoring above 10 (counts `if`/`elif`, loops, `except`, `match` cases, `and`/`or`, comprehension conditions) |
| `DC001` | Unused local variable | Locals that are assigned but never read |
| `DC002` | Unused private function | `_private` functions/methods never referenced in the file |

### Other details

- Import aliases are resolved (`import hashlib as h; h.md5()`, `from os import system`).
- Detected secret values are masked in both terminal and JSON output, so the report itself does not leak them.
- Respects PEP 263 source encoding declarations; syntax errors are reported per file instead of aborting the scan.
- Exit code `1` when anything is found, `0` when clean — ready for CI.

## Usage

```bash
# Scan files or directories
python -m ast_sentinel path/to/project

# Also export results to security_report.json (or a custom path)
python -m ast_sentinel path/to/project --json
python -m ast_sentinel app.py --json out/report.json

# Color control: auto (default), always, never
python -m ast_sentinel app.py --color never
```

Example finding:

```
╭─ CRITICAL  SEC003 · SQL injection risk ──────────────────────────────────────╮
│ Location : app.py:38:5                                                       │
│                                                                              │
│ ▶   38 │     cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")    │
│                                                                              │
│ Issue : The SQL query is built dynamically with an f-string.                 │
│ Fix   : Use a parameterized query: cursor.execute("... WHERE id = ?", (id,)) │
╰──────────────────────────────────────────────────────────────────────────────╯
```

## Using it as a library

```python
from ast_sentinel import SecurityScanner
from ast_sentinel.report import JsonExporter, TerminalReporter

results = SecurityScanner().scan_paths(["src/"])
print(TerminalReporter(color=True).render(results))
JsonExporter("security_report.json").export(results)
```

## Writing a custom rule

Subclass `BaseRule`, declare which AST node types it handles, and yield findings:

```python
import ast
from ast_sentinel import BaseRule, SecurityScanner, Severity
from ast_sentinel.rules import DEFAULT_RULES

class AssertRule(BaseRule):
    rule_id = "SEC100"
    title = "assert used for validation"
    severity = Severity.LOW
    description = "assert statements are stripped when running with -O."
    node_types = (ast.Assert,)

    def check(self, node):
        yield self.finding(node, "assert is removed under python -O.", "Raise an explicit exception instead.")

scanner = SecurityScanner([*DEFAULT_RULES, AssertRule])
```

## Project layout

```
ast_sentinel/
├── core.py            # Severity, Finding, BaseRule, ScanContext, SecurityScanner
├── rules/
│   ├── security.py    # SEC001–SEC004
│   └── quality.py     # CMP001, DC001, DC002
├── report.py          # TerminalReporter, JsonExporter
└── __main__.py        # CLI
tests/
└── test_sentinel.py   # intentionally vulnerable sample + test suite
```

## Tests

```bash
python -m unittest discover -s tests -t . -v

# Or run the demo: prints the full report for the vulnerable sample,
# a line-by-line verification table, writes security_report.json, then runs the tests
python tests/test_sentinel.py
```

The test suite contains an intentionally vulnerable source sample where every flawed line is tagged with `# expect: RULE_ID`. The tests assert that the scanner reports exactly those rule/line pairs — no misses and no extras — and that a clean sample produces zero findings.

> The credentials in the test sample are well-known public examples (the AWS documentation key and the jwt.io sample token) and are not real secrets.

## Limitations

- SQL taint tracking is flow-insensitive within a function (branches are not distinguished).
- Entropy-based detection may flag random-looking identifiers that are not secrets; these are reported as `MEDIUM`.
- Analysis is per file; cross-module usage of private functions is not tracked.
