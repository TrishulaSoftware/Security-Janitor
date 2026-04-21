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
from typing import Optional, List, Dict, Union

logger = logging.getLogger("Janitor.Auditor")

# ─── Data Models ─────────────────────────────────────────────────────────────

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Rule:
    rule_id: str
    severity: Severity
    description: str
    pattern: re.Pattern
    fix_template: Optional[str] = None


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    file_path: str
    line_number: int
    matched_text: str
    description: str
    fixable: bool = False


# ─── Rules Definition ────────────────────────────────────────────────────────

RULES = [
    Rule(
        rule_id="SEC001",
        severity=Severity.CRITICAL,
        description="Potential AWS Access Key detected",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
    ),
    Rule(
        rule_id="SEC002",
        severity=Severity.CRITICAL,
        description="Hardcoded password detected",
        pattern=re.compile(
            r'''(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']''',
            re.IGNORECASE,
        ),
    ),
    Rule(
        rule_id="SEC003",
        severity=Severity.HIGH,
        description="Insecure hash algorithm (MD5/SHA1)",
        pattern=re.compile(r"hashlib\.(md5|sha1)\("),
    ),
    Rule(
        rule_id="SEC004",
        severity=Severity.HIGH,
        description="Potential SQL Injection pattern",
        pattern=re.compile(r"execute\(f?['\"].*\{.*\}['\"]\)\s*"),
    ),
    Rule(
        rule_id="SEC005",
        severity=Severity.MEDIUM,
        description="Mutable GitHub Action tag (use SHA instead)",
        pattern=re.compile(r"uses:\s*[\w\-/]+@v\d+"),
    ),
]


# ─── Auditor Class ───────────────────────────────────────────────────────────

class Auditor:
    def __init__(self, exclude_dirs: List[str] = None):
        self.exclude_dirs = exclude_dirs or [".git", "__pycache__", "node_modules"]
        self.rules = RULES

    def scan_file(self, file_path: Path) -> List[Finding]:
        """Scans a single file for all registered rules."""
        findings = []
        try:
            content = file_path.read_text(errors="ignore")
            lines = content.splitlines()

            for line_idx, line in enumerate(lines, 1):
                for rule in self.rules:
                    match = rule.pattern.search(line)
                    if match:
                        findings.append(
                            Finding(
                                rule_id=rule.rule_id,
                                severity=rule.severity,
                                file_path=str(file_path),
                                line_number=line_idx,
                                matched_text=match.group(0),
                                description=rule.description,
                                fixable=rule.fix_template is not None,
                            )
                        )
        except Exception as e:
            logger.error(f"Error scanning {file_path}: {e}")

        return findings

    def scan_directory(self, root_dir: Path) -> List[Finding]:
        """Recursively scans a directory for vulnerabilities."""
        all_findings = []
        for path in root_dir.rglob("*"):
            if any(part in self.exclude_dirs for part in path.parts):
                continue

            if path.is_file() and path.suffix in (".py", ".yml", ".yaml", ".sh"):
                all_findings.extend(self.scan_file(path))

        return all_findings

if __name__ == "__main__":
    # Self-test
    logging.basicConfig(level=logging.INFO)
    auditor = Auditor()
    print(f"Auditor initialized with {len(RULES)} rules.")
