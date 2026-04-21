"""
AUDITOR — Vulnerability Scanner Module
Part of the Trishula Security Janitor

Scans source files for high-severity vulnerabilities using pattern-based
detection rules. Designed to be extended with LLM-powered analysis.

Current detection capabilities (Phase 1):
    - Hardcoded secrets (API keys, passwords, tokens)
    - Mutable GitHub Actions tags (@vX instead of @sha)
    - SQL injection patterns (string concatenation in queries)
    - Insecure cryptographic usage (MD5, SHA1 for security)
    - Debug/development flags left in production code
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger("Janitor.Auditor")

# ─── Data Models ─────────────────────────────────────────────────────────────


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """A single vulnerability finding."""
    rule_id: str
    severity: Severity
    file_path: str
    line_number: int
    line_content: str
    description: str
    fixable: bool = True
    fix_hint: Optional[str] = None
    context_before: list[str] = field(default_factory=list)
    context_after: list[str] = field(default_factory=list)


# ─── Detection Rules ────────────────────────────────────────────────────────

@dataclass
class Rule:
    """A detection rule definition."""
    rule_id: str
    severity: Severity
    description: str
    pattern: re.Pattern
    file_extensions: list[str]
    fixable: bool = True
    fix_hint: Optional[str] = None
    # Patterns that, if matched on the same line, suppress this rule
    suppress_patterns: list[re.Pattern] = field(default_factory=list)


# Phase 1 rules — pattern-based detection
RULES: list[Rule] = [
    # ── Hardcoded Secrets ────────────────────────────────────────────
    Rule(
        rule_id="SEC001",
        severity=Severity.CRITICAL,
        description="Hardcoded API key or secret detected",
        pattern=re.compile(
            r'''(?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token)'''
            r'''\s*[=:]\s*["\'][A-Za-z0-9+/=_\-]{16,}["\']''',
            re.IGNORECASE,
        ),
        file_extensions=[".py", ".js", ".ts", ".yaml", ".yml", ".json", ".env", ".cfg", ".ini", ".toml"],
        fixable=True,
        fix_hint="Replace hardcoded secret with environment variable reference",
        suppress_patterns=[
            re.compile(r"os\.environ", re.IGNORECASE),
            re.compile(r"process\.env", re.IGNORECASE),
            re.compile(r"#\s*noqa", re.IGNORECASE),
            re.compile(r"example|placeholder|changeme|xxx|your[_-]", re.IGNORECASE),
        ],
    ),
    Rule(
        rule_id="SEC002",
        severity=Severity.CRITICAL,
        description="Hardcoded password detected",
        pattern=re.compile(
            r'''(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']''',
            re.IGNORECASE,
        ),
        file_extensions=[".py", ".js", ".ts", ".yaml", ".yml", ".json", ".cfg", ".ini", ".toml"],
        fixable=True,
        fix_hint="Replace hardcoded password with environment variable reference",
        suppress_patterns=[
            re.compile(r"os\.environ|getenv|process\.env", re.IGNORECASE),
            re.compile(r"#\s*noqa|example|placeholder|changeme|xxx", re.IGNORECASE),
            re.compile(r"password\s*[=:]\s*[\"'][\s]*[\"']", re.IGNORECASE),  # empty password
        ],
    ),
    Rule(
        rule_id="SEC003",
        severity=Severity.HIGH,
        description="AWS-style access key detected",
        pattern=re.compile(r'(?:AKIA|ASIA)[A-Z0-9]{16}'),
        file_extensions=[".py", ".js", ".ts", ".yaml", ".yml", ".json", ".env", ".cfg", ".ini", ".toml", ".tf"],
        fixable=True,
        fix_hint="Remove AWS key and use IAM roles or environment variables",
    ),
    # ── Mutable GitHub Action Tags ───────────────────────────────────
    Rule(
        rule_id="TAG001",
        severity=Severity.HIGH,
        description="Mutable GitHub Action tag reference (vulnerable to tag-poisoning)",
        pattern=re.compile(
            r'uses:\s*[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+@(?:v\d+[\w.]*|latest|main|master)\b',
            re.IGNORECASE,
        ),
        file_extensions=[".yml", ".yaml"],
        fixable=True,
        fix_hint="Pin to immutable 40-character commit SHA",
    ),
    # ── SQL Injection ────────────────────────────────────────────────
    Rule(
        rule_id="INJ001",
        severity=Severity.HIGH,
        description="Potential SQL injection via string concatenation",
        pattern=re.compile(
            r'''(?:execute|cursor\.execute|query)\s*\(\s*["\'].*?["\']\s*\+\s*''',
            re.IGNORECASE,
        ),
        file_extensions=[".py", ".js", ".ts", ".rb", ".php"],
        fixable=True,
        fix_hint="Use parameterized queries instead of string concatenation",
    ),
    Rule(
        rule_id="INJ002",
        severity=Severity.HIGH,
        description="Potential SQL injection via f-string or format()",
        pattern=re.compile(
            r'''(?:execute|cursor\.execute|query)\s*\(\s*f["\'].*?\{.*?\}''',
            re.IGNORECASE,
        ),
        file_extensions=[".py"],
        fixable=True,
        fix_hint="Use parameterized queries instead of f-strings in SQL",
    ),
    # ── Insecure Crypto ──────────────────────────────────────────────
    Rule(
        rule_id="CRY001",
        severity=Severity.MEDIUM,
        description="Insecure hash algorithm used (MD5/SHA1 for security purposes)",
        pattern=re.compile(
            r'''(?:hashlib\.md5|hashlib\.sha1|MD5\.new|SHA\.new)\s*\(''',
            re.IGNORECASE,
        ),
        file_extensions=[".py"],
        fixable=True,
        fix_hint="Use hashlib.sha256() or hashlib.sha3_256() instead",
        suppress_patterns=[
            re.compile(r"checksum|fingerprint|cache|etag", re.IGNORECASE),
        ],
    ),
    # ── Debug Flags ──────────────────────────────────────────────────
    Rule(
        rule_id="DBG001",
        severity=Severity.MEDIUM,
        description="Debug mode enabled in production code",
        pattern=re.compile(
            r'''(?:DEBUG\s*=\s*True|debug\s*=\s*True|app\.debug\s*=\s*True|FLASK_DEBUG\s*=\s*1)''',
        ),
        file_extensions=[".py", ".env", ".cfg", ".ini"],
        fixable=True,
        fix_hint="Set DEBUG=False or use environment variable",
        suppress_patterns=[
            re.compile(r"#.*test|#.*dev|#.*local", re.IGNORECASE),
        ],
    ),
    # ── Prompt Injection Detection ──────────────────────────────────
    Rule(
        rule_id="TS-005",
        severity=Severity.HIGH,
        description="Potential LLM Prompt Injection pattern detected",
        pattern=re.compile(
            r'''(?:ignore\s+all\s+previous\s+instructions|disregard\s+the\s+above|system\s+override|you\s+are\s+now\s+a)''',
            re.IGNORECASE,
        ),
        file_extensions=[".py", ".js", ".ts", ".md", ".txt"],
        fixable=False,
        fix_hint="Review input sanitization and prompt structure to prevent injection.",
    ),
]

# ─── File Type Mapping ───────────────────────────────────────────────────────

SCANNABLE_EXTENSIONS = set()
for rule in RULES:
    SCANNABLE_EXTENSIONS.update(rule.file_extensions)


# ─── Auditor Class ───────────────────────────────────────────────────────────

class Auditor:
    """
    Scans source directories for security vulnerabilities using
    pattern-based detection rules.
    """

    def __init__(
        self,
        rules: Optional[list[Rule]] = None,
        exclude_dirs: Optional[list[str]] = None,
    ):
        self.rules = rules or RULES
        self.exclude_dirs = set(exclude_dirs or [])
        self.logger = logging.getLogger("Janitor.Auditor")
        self._files_scanned = 0
        self._lines_scanned = 0

    def scan_directory(self, directory: Path) -> list[Finding]:
        """Recursively scan a directory for vulnerabilities."""
        self._files_scanned = 0
        self._lines_scanned = 0
        findings: list[Finding] = []

        self.logger.debug("Starting scan of: %s", directory)

        for filepath in self._walk_files(directory):
            file_findings = self.scan_file(filepath)
            findings.extend(file_findings)

        self.logger.debug(
            "Scan complete. Files: %d, Lines: %d, Findings: %d",
            self._files_scanned, self._lines_scanned, len(findings),
        )
        return findings

    def scan_file(self, filepath: Path) -> list[Finding]:
        """Scan a single file against all applicable rules."""
        findings: list[Finding] = []
        suffix = filepath.suffix.lower()

        # Filter rules to those applicable for this file type
        applicable_rules = [
            r for r in self.rules if suffix in r.file_extensions
        ]
        if not applicable_rules:
            return findings

        try:
            lines = filepath.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return findings

        self._files_scanned += 1
        self._lines_scanned += len(lines)

        for line_num, line in enumerate(lines, start=1):
            for rule in applicable_rules:
                if rule.pattern.search(line):
                    # Check suppress patterns
                    suppressed = any(
                        sp.search(line) for sp in rule.suppress_patterns
                    )
                    if suppressed:
                        self.logger.debug(
                            "Suppressed %s at %s:%d", rule.rule_id, filepath, line_num
                        )
                        continue

                    # Gather context lines
                    ctx_start = max(0, line_num - 3)
                    ctx_end = min(len(lines), line_num + 2)

                    finding = Finding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        file_path=str(filepath),
                        line_number=line_num,
                        line_content=line.rstrip(),
                        description=rule.description,
                        fixable=rule.fixable,
                        fix_hint=rule.fix_hint,
                        context_before=lines[ctx_start:line_num - 1],
                        context_after=lines[line_num:ctx_end],
                    )
                    findings.append(finding)

                    self.logger.debug(
                        "Finding: %s [%s] at %s:%d",
                        rule.rule_id, rule.severity.value, filepath, line_num,
                    )

        return findings

    def _walk_files(self, directory: Path):
        """Yield scannable files, skipping excluded directories."""
        try:
            for entry in sorted(directory.iterdir()):
                if entry.is_dir():
                    if entry.name in self.exclude_dirs or entry.name.startswith("."):
                        continue
                    yield from self._walk_files(entry)
                elif entry.is_file() and entry.suffix.lower() in SCANNABLE_EXTENSIONS:
                    yield entry
        except PermissionError:
            self.logger.debug("Permission denied: %s", directory)

    @property
    def stats(self) -> dict:
        """Return scan statistics."""
        return {
            "files_scanned": self._files_scanned,
            "lines_scanned": self._lines_scanned,
            "rules_loaded": len(self.rules),
        }
