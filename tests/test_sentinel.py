"""AST-Sentinel verification tests.

When run directly (python tests/test_sentinel.py) it first prints the colored report and the
line verification table for the intentionally vulnerable sample, writes security_report.json,
then runs the test suite.
"""
from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ast_sentinel import SecurityScanner, Severity  # noqa: E402
from ast_sentinel.report import JsonExporter, TerminalReporter, enable_ansi  # noqa: E402

# Intentionally vulnerable sample. Every flawed line is tagged with "# expect: RULE_ID";
# the tests assert that the scanner reports exactly these (rule, line) pairs.
VULNERABLE_SOURCE = '''\
import os
import pickle
import hashlib
import sqlite3
from hashlib import sha1 as fast_hash

DB_PASSWORD = "Sup3rS3cret!2024"  # expect: SEC001
API_KEY: str = "AKIAIOSFODNN7EXAMPLE"  # expect: SEC001
SESSION = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"  # expect: SEC001
UPLOAD_ID = "q8Zr4Lw2Xv9Tn6Bm1Kc7Hs3Jd5Fg0PyA"  # expect: SEC001
CONFIG = {
    "host": "db.internal",
    "secret_key": "dj4ng0-1ns3cur3-k3y-v4lu3",  # expect: SEC001
}


def connect(user, password="hunter2hunter2"):  # expect: SEC001
    return sqlite3.connect("app.db")


def run_user_code(expr):
    return eval(expr)  # expect: SEC002


def run_script(code):
    exec(code)  # expect: SEC002


def ping(host):
    os.system("ping -c 1 " + host)  # expect: SEC002


def load_session(blob):
    return pickle.loads(blob)  # expect: SEC002


def find_user(cursor, name):
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")  # expect: SEC003


def find_by_id(cursor, uid):
    cursor.execute("SELECT * FROM users WHERE id = %s" % uid)  # expect: SEC003


def delete_user(cursor, uid):
    query = "DELETE FROM users WHERE id = " + uid
    cursor.execute(query)  # expect: SEC003


def safe_query(cursor, uid):
    cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()  # expect: SEC004


def fingerprint(data):
    return fast_hash(data).hexdigest()  # expect: SEC004


def checksum(data):
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def classify(order):  # expect: CMP001
    if order is None:
        return "invalid"
    if order.total > 1000 and order.vip:
        level = "platinum"
    elif order.total > 500 or order.loyal:
        level = "gold"
    elif order.total > 100:
        level = "silver"
    else:
        level = "bronze"
    for line in order.lines:
        if line.qty <= 0:
            continue
        while line.pending:
            line.process()
    try:
        order.validate()
    except ValueError:
        level = "review"
    except KeyError:
        level = "review"
    match order.channel:
        case "web":
            pass
        case "store":
            pass
        case _:
            pass
    return level


def compute_total(items):
    total = 0
    discount = 0.1  # expect: DC001
    for item in items:
        total += item
    return total


def _legacy_helper():  # expect: DC002
    return 42


def _used_helper():
    return 1


def main():
    return _used_helper()
'''

CLEAN_SOURCE = '''\
import hashlib
import json
import os
import subprocess

DB_PASSWORD = os.environ["DB_PASSWORD"]
PASSWORD_PLACEHOLDER = "changeme"
SECRET_HELP = "Read the secret key from an environment variable and never commit it to the repository."
tokenizer_name = "bert-base-uncased"
ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
REQUEST_ID = "550e8400-e29b-41d4-a716-446655440000"


def fetch(cursor, uid):
    cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))
    return cursor.fetchone()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def legacy_checksum(data):
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def parse(text):
    return json.loads(text)


def run(host):
    return subprocess.run(["ping", "-c", "1", host], check=True)


def counter():
    count = 0

    def inc():
        nonlocal count
        count += 1
        return count

    return inc


class Service:
    def __init__(self):
        self._cache = {}

    def get(self, key):
        return self._lookup(key)

    def _lookup(self, key):
        return self._cache.get(key)
'''

_EXPECT = re.compile(r"#\s*expect:\s*([A-Z0-9, ]+)")


def expected_findings(source: str) -> set[tuple[str, int]]:
    expected = set()
    for lineno, line in enumerate(source.splitlines(), start=1):
        if match := _EXPECT.search(line):
            expected.update((rule.strip(), lineno) for rule in match.group(1).split(","))
    return expected


class VulnerableSampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = SecurityScanner().scan_source(VULNERABLE_SOURCE, "vulnerable_sample.py")
        cls.by_line = {(f.rule_id, f.line): f for f in cls.result.findings}

    def test_all_vulnerabilities_found_on_correct_lines(self):
        expected = expected_findings(VULNERABLE_SOURCE)
        self.assertEqual(len(expected), 18)
        self.assertEqual(set(self.by_line), expected)
        self.assertEqual(len(self.result.findings), len(expected), "there must be no duplicate findings")

    def _severity(self, rule_id: str, marker: str) -> Severity:
        line = next(i for i, text in enumerate(VULNERABLE_SOURCE.splitlines(), 1) if marker in text)
        return self.by_line[(rule_id, line)].severity

    def test_severities(self):
        cases = [
            ("SEC001", "DB_PASSWORD =", Severity.HIGH),
            ("SEC001", "API_KEY:", Severity.CRITICAL),  # AWS key pattern
            ("SEC001", "SESSION =", Severity.CRITICAL),  # JWT
            ("SEC001", "UPLOAD_ID =", Severity.MEDIUM),  # entropy only
            ("SEC002", "eval(expr)", Severity.CRITICAL),
            ("SEC002", "os.system(", Severity.HIGH),
            ("SEC003", "cursor.execute(query)", Severity.CRITICAL),
            ("SEC004", "fast_hash(data)", Severity.MEDIUM),
            ("CMP001", "def classify", Severity.MEDIUM),
            ("DC002", "def _legacy_helper", Severity.LOW),
        ]
        for rule_id, marker, severity in cases:
            with self.subTest(rule=rule_id, marker=marker):
                self.assertEqual(self._severity(rule_id, marker), severity)

    def test_every_finding_has_snippet_and_fix(self):
        for f in self.result.findings:
            with self.subTest(rule=f.rule_id, line=f.line):
                source_line = VULNERABLE_SOURCE.splitlines()[f.line - 1]
                if f.rule_id == "SEC001":  # the secret is masked, so it cannot match verbatim
                    self.assertIn("********", f.snippet.splitlines()[0])
                else:
                    self.assertEqual(f.snippet.splitlines()[0], source_line)
                self.assertTrue(f.fix.strip())

    def test_secrets_are_redacted_in_snippets(self):
        report = json.dumps([f.to_dict() for f in self.result.findings])
        for secret in ("Sup3rS3cret!2024", "AKIAIOSFODNN7EXAMPLE", "hunter2hunter2", "q8Zr4Lw2Xv9Tn6Bm1Kc7Hs3Jd5Fg0PyA"):
            self.assertNotIn(secret, report)

    def test_complexity_scores(self):
        scores = {m.name: m.complexity for m in self.result.metrics}
        self.assertEqual(scores["classify"], 14)
        self.assertEqual(scores["compute_total"], 2)
        self.assertEqual(scores["main"], 1)


class CleanCodeTests(unittest.TestCase):
    def test_no_false_positives(self):
        result = SecurityScanner().scan_source(CLEAN_SOURCE, "clean.py")
        self.assertIsNone(result.error)
        self.assertEqual(result.findings, [], [f"{f.rule_id}:{f.line}" for f in result.findings])


class EngineTests(unittest.TestCase):
    def test_aliases_and_hashlib_new(self):
        source = 'import hashlib as h\nfrom os import system as run\nh.md5(b"")\nh.new("SHA1")\nrun("ls")\n'
        found = {(f.rule_id, f.line) for f in SecurityScanner().scan_source(source).findings}
        self.assertEqual(found, {("SEC004", 3), ("SEC004", 4), ("SEC002", 5)})

    def test_sql_taint_is_scoped_and_cleared(self):
        source = (
            "def a(c, x):\n    q = 'SELECT ' + x\n    q = 'SELECT 1'\n    c.execute(q)\n"
            "def b(c, x):\n    q = 'SELECT ' + x\n"
            "def d(c):\n    c.execute(q)\n"
            "def e(c, x):\n    q = 'SELECT * FROM t'\n    q += ' WHERE id = ' + x\n    c.execute(q)\n"
        )
        found = [(f.rule_id, f.line) for f in SecurityScanner().scan_source(source).findings if f.rule_id == "SEC003"]
        self.assertEqual(found, [("SEC003", 12)])

    def test_syntax_error_is_reported(self):
        result = SecurityScanner().scan_source("def broken(:\n", "bad.py")
        self.assertIsNotNone(result.error)
        self.assertEqual(result.findings, [])

    def test_json_export(self):
        result = SecurityScanner().scan_source(VULNERABLE_SOURCE, "vulnerable_sample.py")
        with tempfile.TemporaryDirectory() as tmp:
            path = JsonExporter(Path(tmp) / "security_report.json").export([result])
            data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["summary"]["findings"], len(result.findings))
        self.assertEqual(sum(data["summary"]["by_severity"].values()), len(result.findings))
        self.assertEqual(data["results"][0]["findings"][0]["severity"], result.findings[0].severity.name)

    def test_terminal_report(self):
        result = SecurityScanner().scan_source(VULNERABLE_SOURCE, "vulnerable_sample.py")
        text = TerminalReporter(color=False, width=100).render([result])
        self.assertIn("SEC002 · Dangerous function call", text)
        self.assertIn("Fix   :", text)
        self.assertNotIn("\033[", text)
        self.assertTrue(all(len(line) <= 100 for line in text.splitlines()))


def _demo() -> None:
    result = SecurityScanner().scan_source(VULNERABLE_SOURCE, "vulnerable_sample.py")
    color = enable_ansi()
    print(TerminalReporter(color=color).render([result]))

    found = {(f.rule_id, f.line) for f in result.findings}
    print("\nLINE VERIFICATION (expected # expect tags ↔ findings)")
    for rule_id, line in sorted(expected_findings(VULNERABLE_SOURCE), key=lambda x: x[1]):
        mark = "✔" if (rule_id, line) in found else "✖ MISSING"
        print(f"  {mark}  line {line:>3}  {rule_id}  │ {VULNERABLE_SOURCE.splitlines()[line - 1].strip()[:70]}")
    extra = found - expected_findings(VULNERABLE_SOURCE)
    print(f"  Unexpected findings: {len(extra)} {sorted(extra) if extra else ''}")

    path = JsonExporter(ROOT / "security_report.json").export([result])
    print(f"\nJSON report written: {path}\n")


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    _demo()
    unittest.main(verbosity=2)
