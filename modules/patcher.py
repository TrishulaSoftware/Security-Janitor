"""
PATCHER — The Fix Generator Module
Part of the Trishula Security Janitor

Responsible for generating code patches to address findings.
Dual-tier strategy:
    Tier 1: Deterministic regex-based templates (fast, reliable)
    Tier 2: LLM-powered semantic patching (context-aware fallback)
"""

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Dict

from modules.auditor import Finding, Severity
from modules.llm_connector import LLMConnector

logger = logging.getLogger("Janitor.Patcher")

@dataclass
class PatchResult:
    success: bool
    finding: Finding
    description: str
    strategy: str  # "regex_template" or "llm_semantic_patch"
    diff: Optional[str] = None


class Patcher:
    def __init__(self, llm_connector: Optional[LLMConnector] = None, enable_llm: bool = True):
        self.llm_connector = llm_connector
        self.enable_llm = enable_llm and llm_connector is not None

    def patch(self, finding: Finding) -> PatchResult:
        """Attempt to patch a finding using the dual-tier strategy."""
        
        # Tier 1: Regex-based patching (Phase 1)
        # For now, we only have few deterministic templates.
        # Most patches in Phase 2 will go to Tier 2.
        
        if finding.rule_id == "SEC005": # Mutable tag
            return self._patch_mutable_tag(finding)
        
        # Tier 2: LLM Fallback
        if self.enable_llm:
            return self._patch_with_llm(finding)
        
        return PatchResult(
            success=False,
            finding=finding,
            description="No matching regex template and LLM disabled.",
            strategy="none"
        )

    def _patch_mutable_tag(self, finding: Finding) -> PatchResult:
        """Deterministic fix for mutable tags: replace @vX with a placeholder SHA."""
        # In a real tool, we would resolve the tag to a SHA.
        # Here we use a known safe SHA or a placeholder.
        safe_sha = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"
        
        try:
            file_path = Path(finding.file_path)
            lines = file_path.read_text().splitlines()
            
            line_idx = finding.line_number - 1
            original_line = lines[line_idx]
            
            # Replace @v... with @sha
            new_line = original_line.split("@")[0] + "@" + safe_sha
            
            if self._apply_patch(file_path, line_idx, new_line):
                return PatchResult(
                    success=True,
                    finding=finding,
                    description=f"Pinned mutable tag to {safe_sha[:7]}",
                    strategy="regex_template"
                )
        except Exception as e:
            logger.error(f"Regex patch failed for {finding.file_path}: {e}")

        return PatchResult(
            success=False,
            finding=finding,
            description="Regex patch application failed.",
            strategy="regex_template"
        )

    def _patch_with_llm(self, finding: Finding) -> PatchResult:
        """Tier 2: Semantic patching via LLM."""
        logger.info(f"Tier 2: Requesting semantic patch for {finding.rule_id}")
        
        try:
            prompt = self._build_patch_prompt(finding)
            response = self.llm_connector.generate_patch(prompt)
            
            if response and response.get("fixed_code"):
                file_path = Path(finding.file_path)
                if self._apply_patch(file_path, finding.line_number - 1, response["fixed_code"]):
                    return PatchResult(
                        success=True,
                        finding=finding,
                        description=response.get("explanation", "LLM-generated semantic fix"),
                        strategy="llm_semantic_patch"
                    )
        except Exception as e:
            logger.error(f"LLM patch failed: {e}")

        return PatchResult(
            success=False,
            finding=finding,
            description="LLM failed to generate a valid patch.",
            strategy="llm_semantic_patch"
        )

    def _build_patch_prompt(self, finding: Finding) -> str:
        """Build the prompt for the LLM to generate a fix."""
        # Simple prompt for now
        return f"Fix this security vulnerability ({finding.rule_id}: {finding.description}) in the following line: {finding.matched_text}"

    def _apply_patch(self, file_path: Path, line_idx: int, new_line: str) -> bool:
        """Writes the patch to the filesystem."""
        try:
            lines = file_path.read_text().splitlines()
            lines[line_idx] = new_line
            file_path.write_text("\n".join(lines) + "\n")
            return True
        except Exception as e:
            logger.error(f"Failed to write patch to {file_path}: {e}")
            return False
