"""
PATCHER — Agentic Fix Module (Phase 2: LLM Integration)
Part of the Trishula Security Janitor

Takes findings from the Auditor and generates fixes using a two-tier strategy:
    Tier 1: Deterministic regex-based fixes (fast, predictable)
    Tier 2: LLM-powered semantic patches (for complex vulns regex can't handle)

Architecture:
    - Each rule_id maps to a FixStrategy
    - FixStrategy.apply() reads the file, transforms the vulnerable line, writes back
    - SemanticPatcher wraps the LLM connector for context-aware code rewrites
    - All fixes are logged with before/after diffs
"""

import logging
import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from modules.auditor import Finding
from modules.llm_connector import LLMConfig, LLMConnector, LLMMode

logger = logging.getLogger("Janitor.Patcher")

# ─── Data Models ─────────────────────────────────────────────────────────────


@dataclass
class PatchResult:
    """Result of a patch attempt."""
    success: bool
    finding: Finding
    description: str
    original_line: str
    patched_line: str
    strategy: str


# ─── Fix Strategies (Tier 1: Regex) ─────────────────────────────────────────

class FixStrategy(ABC):
    """Base class for all fix strategies."""

    @abstractmethod
    def apply(self, finding: Finding, lines: list[str]) -> Optional[str]:
        """
        Apply the fix to the specific line.

        Args:
            finding: The vulnerability finding
            lines: All lines in the file (for context)

        Returns:
            The fixed line content, or None if fix cannot be applied.
        """
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        ...


class HardcodedSecretFix(FixStrategy):
    """Replace hardcoded secrets with environment variable lookups."""

    name = "env_var_replacement"

    _key_pattern = re.compile(
        r'''((?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|pwd))'''
        r'''\s*([=:])\s*["\']([^"\']+)["\']''',
        re.IGNORECASE,
    )

    def apply(self, finding: Finding, lines: list[str]) -> Optional[str]:
        line = finding.line_content
        match = self._key_pattern.search(line)
        if not match:
            return None

        var_name = match.group(1).strip()
        operator = match.group(2)
        env_var_name = var_name.upper().replace("-", "_").replace(" ", "_")

        filepath = Path(finding.file_path)
        suffix = filepath.suffix.lower()

        if suffix == ".py":
            replacement = f'{var_name} {operator} os.environ.get("{env_var_name}", "")'
        elif suffix in (".js", ".ts"):
            replacement = f'{var_name} {operator} process.env.{env_var_name} || ""'
        elif suffix in (".yaml", ".yml"):
            replacement = f'{var_name}{operator} ${{{{ secrets.{env_var_name} }}}}'
        elif suffix in (".env", ".cfg", ".ini"):
            replacement = f'{var_name}{operator}  # REDACTED — set via environment'
        else:
            replacement = f'{var_name} {operator} os.environ.get("{env_var_name}", "")'

        indent = len(line) - len(line.lstrip())
        return " " * indent + replacement


class MutableTagFix(FixStrategy):
    """Replace mutable GitHub Action tags with placeholder SHA references."""

    name = "sha_pin_replacement"

    _tag_pattern = re.compile(
        r'(uses:\s*[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+)@(v\d+[\w.]*|latest|main|master)',
        re.IGNORECASE,
    )

    def apply(self, finding: Finding, lines: list[str]) -> Optional[str]:
        line = finding.line_content
        match = self._tag_pattern.search(line)
        if not match:
            return None

        action_ref = match.group(1)
        old_tag = match.group(2)

        placeholder_sha = "0" * 40
        replacement = f"{action_ref}@{placeholder_sha}  # TODO: resolve SHA for @{old_tag}"

        indent = len(line) - len(line.lstrip())
        return " " * indent + replacement


class InsecureCryptoFix(FixStrategy):
    """Replace MD5/SHA1 with SHA-256."""

    name = "secure_hash_replacement"

    def apply(self, finding: Finding, lines: list[str]) -> Optional[str]:
        line = finding.line_content
        patched = line.replace("hashlib.md5", "hashlib.sha256")
        patched = patched.replace("hashlib.sha1", "hashlib.sha256")
        patched = patched.replace("MD5.new", "SHA256.new")
        patched = patched.replace("SHA.new", "SHA256.new")

        if patched != line:
            return patched
        return None


class DebugFlagFix(FixStrategy):
    """Disable debug flags."""

    name = "debug_disable"

    def apply(self, finding: Finding, lines: list[str]) -> Optional[str]:
        line = finding.line_content
        patched = re.sub(r'(DEBUG\s*=\s*)True', r'\1False', line, flags=re.IGNORECASE)
        patched = re.sub(r'(FLASK_DEBUG\s*=\s*)1', r'\g<1>0', patched, flags=re.IGNORECASE)
        patched = re.sub(r'(app\.debug\s*=\s*)True', r'\1False', patched, flags=re.IGNORECASE)

        if patched != line:
            return patched
        return None


class AWSKeyFix(FixStrategy):
    """Redact hardcoded AWS keys."""

    name = "aws_key_redaction"

    def apply(self, finding: Finding, lines: list[str]) -> Optional[str]:
        line = finding.line_content
        indent = len(line) - len(line.lstrip())
        return (
            " " * indent
            + "# SECURITY: AWS key redacted by Security Janitor — use IAM roles"
            + "\n"
            + " " * indent
            + re.sub(r'(?:AKIA|ASIA)[A-Z0-9]{16}', '"REDACTED"', line.lstrip())
        )


class SQLInjectionFix(FixStrategy):
    """Replace string-concatenated SQL with parameterized queries (deterministic)."""

    name = "parameterized_query_regex"

    # Pattern: cursor.execute("... '" + variable + "'...")
    CONCAT_VAR_RE = re.compile(r'\+\s*(\w+)\s*\+')

    # Pattern: cursor.execute(f"...{variable}...")
    FSTRING_RE = re.compile(r'execute\(f(["\'])(.*?)\1\)')

    # Pattern: {variable_name} inside an f-string
    FSTRING_VAR_RE = re.compile(r'\{(\w+)\}')

    def apply(self, finding: Finding, lines: list[str]) -> Optional[str]:
        line = finding.line_content
        indent = len(line) - len(line.lstrip())
        stripped = line.lstrip()

        # Case 1: String concatenation  →  parameterized query
        if "+" in stripped and "execute" in stripped:
            var_match = self.CONCAT_VAR_RE.search(stripped)
            if var_match:
                var_name = var_match.group(1)
                # Extract the SQL prefix up to the first quote before concatenation
                exec_match = re.match(r'(\w+\.execute\()', stripped)
                prefix = exec_match.group(1) if exec_match else "cursor.execute("
                # Extract SQL string content before the variable
                sql_match = re.search(r'execute\(\s*["\'](.+?)["\']', stripped)
                if sql_match:
                    sql_text = sql_match.group(1)
                    # Replace the trailing part before variable with placeholder
                    sql_text = sql_text.rstrip().rstrip("'").rstrip('"')
                    fixed = prefix + '"' + sql_text + '?", (' + var_name + ',))'
                    return " " * indent + fixed

        # Case 2: f-string  →  parameterized query
        fstr_match = self.FSTRING_RE.search(stripped)
        if fstr_match:
            quote = fstr_match.group(1)
            sql_body = fstr_match.group(2)
            # Find all {var} references
            var_names = self.FSTRING_VAR_RE.findall(sql_body)
            if var_names:
                # Replace {var} with ? placeholders
                clean_sql = self.FSTRING_VAR_RE.sub("?", sql_body)
                # Remove any leftover format specifiers around the placeholder
                clean_sql = clean_sql.replace("'?'", "?").replace("%?%", "?")
                params = ", ".join(var_names)
                tuple_str = "(" + params + ",)" if len(var_names) == 1 else "(" + params + ")"
                fixed = re.sub(
                    r'execute\(f["\'].*?["\']\)',
                    'execute("' + clean_sql + '", ' + tuple_str + ")",
                    stripped,
                )
                return " " * indent + fixed

        # Case 3: Generic fallback — add security comment + preserve original
        return (
            " " * indent
            + "# SECURITY: SQL injection risk — convert to parameterized query"
            + "\n"
            + " " * indent
            + stripped
        )


# ─── Tier 2: Semantic Patcher (LLM-Powered) ─────────────────────────────────

DEVSECOPS_SYSTEM_PROMPT = """You are an autonomous DevSecOps agent. Your ONLY job is to fix security vulnerabilities in code.

RULES:
1. Return ONLY the securely patched code block. No markdown fences. No explanations.
2. Preserve the original indentation exactly.
3. Preserve all surrounding logic — change ONLY the vulnerable line(s).
4. The fix must be a drop-in replacement for the vulnerable code region.
5. Do NOT add comments explaining the fix unless the comment replaces a hardcoded secret.
6. Do NOT import new libraries unless absolutely necessary for the fix.
7. If you cannot fix the vulnerability, return the original code unchanged.

OUTPUT FORMAT:
Return raw code only. No ```python``` fences. No "Here is the fix" preamble. Just code."""


class SemanticPatcher(FixStrategy):
    """
    LLM-powered semantic patching for vulnerabilities that regex cannot handle.

    Sends the vulnerable code block with surrounding context to the LLM,
    which generates a secure replacement. The output is sanitized and
    validated before being applied.
    """

    name = "llm_semantic_patch"

    # Context window: lines before/after the vulnerable line to send to the LLM
    CONTEXT_WINDOW = 10

    def __init__(self, llm: Optional[LLMConnector] = None):
        self._llm = llm
        self._logger = logging.getLogger("Janitor.SemanticPatcher")

    @property
    def llm(self) -> LLMConnector:
        """Lazy-initialize the LLM connector."""
        if self._llm is None:
            self._llm = LLMConnector()
        return self._llm

    def apply(self, finding: Finding, lines: list[str]) -> Optional[str]:
        """Generate a semantic fix using the LLM."""
        self._logger.info(
            "LLM semantic patch requested for %s:%d [%s]",
            finding.file_path, finding.line_number, finding.rule_id,
        )

        # Build the context window
        target_idx = finding.line_number - 1
        ctx_start = max(0, target_idx - self.CONTEXT_WINDOW)
        ctx_end = min(len(lines), target_idx + self.CONTEXT_WINDOW + 1)

        context_block = lines[ctx_start:ctx_end]
        vulnerable_line = lines[target_idx] if target_idx < len(lines) else finding.line_content

        # Build the user prompt
        user_prompt = self._build_prompt(finding, context_block, vulnerable_line, ctx_start)

        self._logger.debug("LLM prompt:\n%s", user_prompt)

        # Call the LLM
        try:
            fixed_code = self.llm.generate_code(DEVSECOPS_SYSTEM_PROMPT, user_prompt)
        except Exception as e:
            self._logger.error("LLM call failed: %s", e)
            return None

        if not fixed_code:
            self._logger.warning("LLM returned empty response")
            return None

        self._logger.info("LLM returned %d chars of patched code", len(fixed_code))
        self._logger.debug("LLM output:\n%s", fixed_code)

        # Validate: the fix should not be identical to the original
        original_block = "\n".join(context_block).strip()
        if fixed_code.strip() == original_block:
            self._logger.warning("LLM returned identical code — no fix generated")
            return None

        # Extract just the fixed vulnerable line from the LLM output.
        # The LLM may return the full context block — we need to identify
        # which line corresponds to the fix.
        fixed_line = self._extract_fixed_line(
            fixed_code, vulnerable_line, context_block, target_idx - ctx_start,
        )

        if fixed_line is None:
            self._logger.warning("Could not extract fixed line from LLM output")
            return None

        self._logger.info(
            "Semantic fix extracted:\n  BEFORE: %s\n  AFTER:  %s",
            vulnerable_line.strip(), fixed_line.strip(),
        )

        return fixed_line

    def _build_prompt(
        self,
        finding: Finding,
        context_block: list[str],
        vulnerable_line: str,
        block_start_line: int,
    ) -> str:
        """Build the user prompt for the LLM."""
        numbered_context = "\n".join(
            f"{block_start_line + i + 1:4d} | {line}"
            for i, line in enumerate(context_block)
        )

        filepath = Path(finding.file_path)

        return f"""VULNERABILITY: {finding.rule_id} — {finding.description}
SEVERITY: {finding.severity.value}
FILE: {filepath.name} ({filepath.suffix})
VULNERABLE LINE NUMBER: {finding.line_number}

CODE CONTEXT:
{numbered_context}

THE VULNERABLE LINE:
{finding.line_number:4d} | {vulnerable_line}

FIX HINT: {finding.fix_hint or 'No hint available.'}

Return ONLY the fixed version of the vulnerable line (line {finding.line_number}). Preserve exact indentation."""

    def _extract_fixed_line(
        self,
        llm_output: str,
        original_line: str,
        context_block: list[str],
        target_offset: int,
    ) -> Optional[str]:
        """Extract the fixed line from the LLM's output.

        The LLM might return:
        1. Just the fixed line (ideal)
        2. The full context block with the fix applied
        3. Multiple lines including the fix

        We handle all three cases.
        """
        output_lines = llm_output.splitlines()

        # Case 1: Single line output
        if len(output_lines) == 1:
            return output_lines[0]

        # Case 2: Output has same number of lines as context — extract by offset
        if len(output_lines) == len(context_block):
            return output_lines[target_offset]

        # Case 3: Look for the line that differs from the original
        original_stripped = original_line.strip()
        for out_line in output_lines:
            stripped = out_line.strip()
            # Skip lines that match unchanged context
            if stripped in [cl.strip() for cl in context_block]:
                continue
            # Skip empty lines
            if not stripped:
                continue
            # Skip line number prefixes (e.g., "  42 | fixed_code")
            cleaned = re.sub(r'^\s*\d+\s*\|\s*', '', out_line)
            if cleaned.strip() and cleaned.strip() != original_stripped:
                # Preserve the original indentation
                indent = len(original_line) - len(original_line.lstrip())
                return " " * indent + cleaned.strip()

        # Case 4: If we still can't find it, return the first non-empty,
        # non-context line
        for out_line in output_lines:
            stripped = out_line.strip()
            if stripped and stripped != original_stripped:
                indent = len(original_line) - len(original_line.lstrip())
                return " " * indent + stripped

        return None


# ─── Strategy Registry (Phase 2: Dual-Tier) ─────────────────────────────────

# Tier 1: Deterministic regex strategies
REGEX_STRATEGY_MAP: dict[str, FixStrategy] = {
    "SEC001": HardcodedSecretFix(),
    "SEC002": HardcodedSecretFix(),
    "SEC003": AWSKeyFix(),
    "TAG001": MutableTagFix(),
    "INJ001": SQLInjectionFix(),
    "INJ002": SQLInjectionFix(),
    "CRY001": InsecureCryptoFix(),
    "DBG001": DebugFlagFix(),
}

# Rules that should prefer LLM (Tier 2) due to complexity
LLM_PREFERRED_RULES = {"INJ001", "INJ002"}


# ─── Unified Patcher Class (Phase 2) ────────────────────────────────────────

class Patcher:
    """
    The dual-tier agentic patching engine.

    Tier 1 (Regex): Fast, deterministic pattern-based fixes.
    Tier 2 (LLM):   Semantic, context-aware fixes for complex vulnerabilities.

    Fallback logic:
        1. If rule_id has a regex strategy AND is not LLM-preferred → try regex first
        2. If regex fails or rule is LLM-preferred → try LLM semantic patch
        3. If LLM is unavailable (no endpoint) → regex-only mode (graceful degradation)
    """

    def __init__(
        self,
        strategies: Optional[dict[str, FixStrategy]] = None,
        llm_connector: Optional[LLMConnector] = None,
        enable_llm: bool = True,
    ):
        self.strategies = strategies or REGEX_STRATEGY_MAP
        self.enable_llm = enable_llm
        self._semantic_patcher: Optional[SemanticPatcher] = None
        self.logger = logging.getLogger("Janitor.Patcher")

        # Initialize the semantic patcher if LLM is enabled
        if enable_llm:
            try:
                self._semantic_patcher = SemanticPatcher(llm=llm_connector)
                self.logger.info("Tier 2 (LLM) semantic patching: ENABLED")
            except Exception as e:
                self.logger.warning("Tier 2 (LLM) initialization failed: %s", e)
                self._semantic_patcher = None
        else:
            self.logger.info("Tier 2 (LLM) semantic patching: DISABLED")

    def patch(self, finding: Finding) -> PatchResult:
        """Attempt to patch a single finding using the dual-tier strategy."""
        rule_id = finding.rule_id
        is_llm_preferred = rule_id in LLM_PREFERRED_RULES
        regex_strategy = self.strategies.get(rule_id)

        # Read the file
        filepath = Path(finding.file_path)
        try:
            content = filepath.read_text(encoding="utf-8")
            lines = content.splitlines()
        except OSError as e:
            return PatchResult(
                success=False, finding=finding,
                description=f"Cannot read file: {e}",
                original_line=finding.line_content, patched_line="",
                strategy="none",
            )

        target_idx = finding.line_number - 1
        if target_idx < 0 or target_idx >= len(lines):
            return PatchResult(
                success=False, finding=finding,
                description=f"Line number {finding.line_number} out of range",
                original_line=finding.line_content, patched_line="",
                strategy="none",
            )

        original = lines[target_idx]
        fixed_line: Optional[str] = None
        strategy_used = "none"

        # ── Decision: Regex first or LLM first? ─────────────────────
        if is_llm_preferred and self._semantic_patcher:
            # Complex rule → try LLM first, fall back to regex
            self.logger.info(
                "[%s] LLM-preferred rule — attempting semantic patch first",
                rule_id,
            )
            fixed_line = self._try_semantic_patch(finding, lines)
            if fixed_line is not None:
                strategy_used = "llm_semantic_patch"
            elif regex_strategy:
                self.logger.info(
                    "[%s] LLM failed — falling back to regex strategy",
                    rule_id,
                )
                fixed_line = regex_strategy.apply(finding, lines)
                if fixed_line is not None:
                    strategy_used = regex_strategy.name

        elif regex_strategy:
            # Standard rule → try regex first, fall back to LLM
            fixed_line = regex_strategy.apply(finding, lines)
            if fixed_line is not None:
                strategy_used = regex_strategy.name
            elif self._semantic_patcher:
                self.logger.info(
                    "[%s] Regex strategy returned None — escalating to LLM",
                    rule_id,
                )
                fixed_line = self._try_semantic_patch(finding, lines)
                if fixed_line is not None:
                    strategy_used = "llm_semantic_patch"

        elif self._semantic_patcher:
            # No regex strategy at all → LLM only
            self.logger.info(
                "[%s] No regex strategy — using LLM semantic patch",
                rule_id,
            )
            fixed_line = self._try_semantic_patch(finding, lines)
            if fixed_line is not None:
                strategy_used = "llm_semantic_patch"

        # ── Apply the fix ────────────────────────────────────────────
        if fixed_line is None:
            return PatchResult(
                success=False, finding=finding,
                description="No strategy (regex or LLM) could generate a fix",
                original_line=original, patched_line="",
                strategy=strategy_used,
            )

        # Write the patched file
        lines[target_idx] = fixed_line
        try:
            filepath.write_text("\n".join(lines) + "\n", encoding="utf-8")
        except OSError as e:
            return PatchResult(
                success=False, finding=finding,
                description=f"Cannot write file: {e}",
                original_line=original, patched_line=fixed_line,
                strategy=strategy_used,
            )

        self.logger.info(
            "Patched %s:%d [%s] via %s",
            filepath.name, finding.line_number, rule_id, strategy_used,
        )
        self.logger.debug("  BEFORE: %s", original.strip())
        self.logger.debug("  AFTER:  %s", fixed_line.strip())

        return PatchResult(
            success=True, finding=finding,
            description=f"Fixed via {strategy_used}",
            original_line=original, patched_line=fixed_line,
            strategy=strategy_used,
        )

    def _try_semantic_patch(self, finding: Finding, lines: list[str]) -> Optional[str]:
        """Attempt LLM semantic patching with error handling."""
        if not self._semantic_patcher:
            return None
        try:
            return self._semantic_patcher.apply(finding, lines)
        except Exception as e:
            self.logger.error(
                "Semantic patch failed for %s:%d: %s",
                finding.file_path, finding.line_number, e,
            )
            return None
