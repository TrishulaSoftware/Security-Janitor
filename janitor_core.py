"""
JANITOR CORE — The Autonomous Security Loop Orchestrator (Phase 2)
Part of the Trishula Security Janitor

The main event loop that watches a target directory, triggers the auditor,
dispatches findings to the dual-tier patcher (regex → LLM fallback),
and commits fixes via git_ops.

Usage:
    python janitor_core.py --target /path/to/repo
    python janitor_core.py --target /path/to/repo --watch      # Continuous mode
    python janitor_core.py --target /path/to/repo --dry-run    # Report only
    python janitor_core.py --target /path/to/repo --llm local  # Use local Ollama
    python janitor_core.py --target /path/to/repo --llm openai # Use OpenAI API
    python janitor_core.py --target /path/to/repo --no-llm     # Regex only (Phase 1 mode)
"""

import argparse
import hashlib
import logging
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict

from modules.auditor import Auditor, Finding, Severity
from modules.git_ops import GitOperator
from modules.llm_connector import LLMConfig, LLMConnector, LLMMode
from modules.patcher import Patcher

# ─── Configuration ───────────────────────────────────────────────────────────

LOG_FORMAT = (
    "%(asctime)s │ %(levelname)-8s │ %(name)-24s │ %(message)s"
)
LOG_DATE_FORMAT = "%H:%M:%S"
LOG_FILE = "janitor_strike.log"


class RunMode(Enum):
    SINGLE = "single"
    WATCH = "watch"


@dataclass
class JanitorConfig:
    """Runtime configuration for the Security Janitor."""
    target_path: Path
    mode: RunMode = RunMode.SINGLE
    dry_run: bool = False
    watch_interval: int = 30
    auto_commit: bool = True
    branch_prefix: str = "janitor-fix"
    log_level: str = "INFO"
    llm_mode: Optional[str] = None      # "local", "openai", "anthropic", or None
    llm_model: Optional[str] = None
    enable_llm: bool = True
    exclude_dirs: List[str] = field(default_factory=lambda: [
        ".git", "__pycache__", "node_modules", ".venv", "venv",
        ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
    ])


# ─── The Janitor ─────────────────────────────────────────────────────────────

class SecurityJanitor:
    """
    The autonomous security loop (Phase 2: LLM-augmented).

    Lifecycle:
        1. SCAN   — Auditor sweeps the target for vulnerabilities
        2. TRIAGE — Findings are scored and filtered
        3. PATCH  — Dual-tier patcher: regex first, LLM fallback
        4. COMMIT — GitOperator branches, stages, and commits
        5. REPORT — Summary of all actions taken
    """

    def __init__(self, config: JanitorConfig):
        self.config = config
        self.logger = logging.getLogger("Janitor.Core")
        self.auditor = Auditor(exclude_dirs=config.exclude_dirs)
        self.git_ops = None
        self._run_count = 0
        self._total_findings = 0
        self._total_patches = 0
        self._total_regex_patches = 0
        self._total_llm_patches = 0
        self._total_commits = 0

        # Initialize the dual-tier patcher
        self.patcher = self._init_patcher()

    def _init_patcher(self) -> Patcher:
        """Initialize the Patcher with optional LLM backend."""
        llm_connector = None

        if self.config.enable_llm and self.config.llm_mode:
            try:
                llm_mode = LLMMode(self.config.llm_mode)
                llm_config = LLMConfig(
                    mode=llm_mode,
                    model=self.config.llm_model,
                )
                llm_connector = LLMConnector(config=llm_config)
                self.logger.info(
                    "LLM backend armed: %s (%s)",
                    llm_mode.value, llm_config.model,
                )
            except Exception as e:
                self.logger.warning("LLM initialization failed: %s", e)
                self.logger.warning("Falling back to regex-only mode.")

        return Patcher(
            llm_connector=llm_connector,
            enable_llm=self.config.enable_llm and llm_connector is not None,
        )

    def initialize(self) -> bool:
        """Validate the target and initialize subsystems."""
        llm_status = "DISABLED"
        if self.config.enable_llm and self.config.llm_mode:
            llm_status = f"ARMED ({self.config.llm_mode})"

        self.logger.info("=" * 70)
        self.logger.info("  SECURITY JANITOR v2.0 — Autonomous DevSecOps Agent")
        self.logger.info("  Target:  %s", self.config.target_path)
        self.logger.info("  Mode:    %s", self.config.mode.value)
        self.logger.info("  Dry Run: %s", self.config.dry_run)
        self.logger.info("  Tier 1:  Regex (deterministic)")
        self.logger.info("  Tier 2:  LLM (%s)", llm_status)
        self.logger.info("  Log:     %s", LOG_FILE)
        self.logger.info("=" * 70)

        if not self.config.target_path.exists():
            self.logger.error("Target path does not exist: %s", self.config.target_path)
            return False

        if not self.config.target_path.is_dir():
            self.logger.error("Target path is not a directory: %s", self.config.target_path)
            return False

        # Initialize git operator
        try:
            self.git_ops = GitOperator(self.config.target_path)
            self.logger.info("Git repository detected: %s", self.git_ops.repo_root)
        except Exception as e:
            self.logger.warning("No git repository found: %s", e)
            self.logger.warning("Git operations will be disabled.")
            self.git_ops = None

        return True

    def run(self):
        """Execute the main loop."""
        if not self.initialize():
            sys.exit(1)

        if self.config.mode == RunMode.SINGLE:
            self._execute_cycle()
        elif self.config.mode == RunMode.WATCH:
            self._watch_loop()

        self._print_summary()

    def _watch_loop(self):
        """Continuous watch mode — scan at regular intervals."""
        self.logger.info(
            "Entering WATCH mode. Scanning every %ds. Ctrl+C to stop.",
            self.config.watch_interval,
        )
        try:
            while True:
                self._execute_cycle()
                self.logger.info(
                    "Next scan in %ds...", self.config.watch_interval
                )
                time.sleep(self.config.watch_interval)
        except KeyboardInterrupt:
            self.logger.info("Watch mode interrupted. Shutting down.")

    def _execute_cycle(self):
        """Execute one full audit-patch-commit cycle."""
        self._run_count += 1
        cycle_id = hashlib.md5(
            f"{time.time()}-{self._run_count}".encode()
        ).hexdigest()[:8]

        self.logger.info("─" * 70)
        self.logger.info("CYCLE %d [%s] — Starting", self._run_count, cycle_id)

        # Phase 1: SCAN
        self.logger.info("[Phase 1/4] SCAN — Auditing target directory...")
        findings = self.auditor.scan_directory(self.config.target_path)
        self._total_findings += len(findings)

        if not findings:
            self.logger.info("[Phase 1/4] SCAN — Clean. Zero findings.")
            return

        self.logger.info(
            "[Phase 1/4] SCAN — %d finding(s) detected.", len(findings)
        )

        # Phase 2: TRIAGE
        self.logger.info("[Phase 2/4] TRIAGE — Filtering actionable findings...")
        actionable = self._triage(findings)

        if not actionable:
            self.logger.info("[Phase 2/4] TRIAGE — No actionable findings after filtering.")
            return

        self.logger.info(
            "[Phase 2/4] TRIAGE — %d actionable finding(s).", len(actionable)
        )
        for i, finding in enumerate(actionable, 1):
            self.logger.info(
                "  [%d] %s | %s | %s:%d | %s",
                i, finding.rule_id, finding.severity.value, finding.file_path, finding.line_number,
                finding.description[:60],
            )

        if self.config.dry_run:
            self.logger.info("[DRY RUN] Stopping before patch phase.")
            return

        # Phase 3: PATCH (Dual-Tier)
        self.logger.info("[Phase 3/4] PATCH — Generating fixes (Tier 1: Regex → Tier 2: LLM)...")
        patch_results = []
        for finding in actionable:
            result = self.patcher.patch(finding)
            patch_results.append(result)
            if result.success:
                self._total_patches += 1
                if result.strategy == "llm_semantic_patch":
                    self._total_llm_patches += 1
                    tag = "🤖 LLM"
                else:
                    self._total_regex_patches += 1
                    tag = "⚡ REG"
                self.logger.info(
                    "  ✅ [%s] Patched: %s:%d — %s",
                    tag, finding.file_path, finding.line_number, result.description,
                )
            else:
                self.logger.warning(
                    "  ❌ Failed:  %s:%d — %s",
                    finding.file_path, finding.line_number, result.description,
                )

        successful_patches = [r for r in patch_results if r.success]
        if not successful_patches:
            self.logger.info("[Phase 3/4] PATCH — No successful patches to commit.")
            return

        # Phase 4: COMMIT
        if self.git_ops and self.config.auto_commit:
            self.logger.info("[Phase 4/4] COMMIT — Branching and committing fixes...")
            branch_name = f"{self.config.branch_prefix}-{cycle_id}"

            try:
                self.git_ops.create_branch(branch_name)
                self.logger.info("  Branch created: %s", branch_name)

                patched_files = [
                    r.finding.file_path for r in successful_patches
                ]
                self.git_ops.stage_files(patched_files)

                commit_msg = self._build_commit_message(successful_patches)
                commit_sha = self.git_ops.commit(commit_msg)
                self._total_commits += 1
                self.logger.info("  Committed: %s (%s)", commit_sha[:12], branch_name)

                self.git_ops.checkout_original()
                self.logger.info("  Returned to original branch.")

            except Exception as e:
                self.logger.error("  Git operation failed: %s", e)
                try:
                    self.git_ops.abort()
                except Exception:
                    pass
        else:
            self.logger.info("[Phase 4/4] COMMIT — Skipped (git disabled or auto-commit off).")

        self.logger.info("CYCLE %d [%s] — Complete", self._run_count, cycle_id)

    def _triage(self, findings: List[Finding]) -> List[Finding]:
        """Filter findings to only actionable items (HIGH/CRITICAL)."""
        return [
            f for f in findings
            if f.severity in (Severity.HIGH, Severity.CRITICAL)
            and f.fixable
        ]

    def _build_commit_message(self, patches: List) -> str:
        """Generate a structured commit message from patch results."""
        regex_count = sum(1 for p in patches if p.strategy != "llm_semantic_patch")
        llm_count = sum(1 for p in patches if p.strategy == "llm_semantic_patch")

        lines = [
            "fix(security): autonomous patch by Security Janitor v2.0",
            "",
            f"Patches: {len(patches)} ({regex_count} regex, {llm_count} LLM)",
            "",
            "Findings addressed:",
        ]
        for p in patches:
            tier = "LLM" if p.strategy == "llm_semantic_patch" else "REG"
            lines.append(
                f"  - [{p.finding.severity.value}] [{tier}] {p.finding.rule_id}: {p.description}"
            )

        lines.extend([
            "",
            "Generated by: Trishula Security Janitor v2.0",
            "Mode: Autonomous | Dual-Tier (Regex + LLM)",
        ])
        return "\n".join(lines)

    def _print_summary(self):
        """Print a final summary of all cycles."""
        self.logger.info("=" * 70)
        self.logger.info("  SECURITY JANITOR v2.0 — SESSION SUMMARY")
        self.logger.info("  Cycles run:          %d", self._run_count)
        self.logger.info("  Total findings:      %d", self._total_findings)
        self.logger.info("  Patches applied:     %d", self._total_patches)
        self.logger.info("    ├─ Regex (Tier 1): %d", self._total_regex_patches)
        self.logger.info("    └─ LLM   (Tier 2): %d", self._total_llm_patches)
        self.logger.info("  Commits created:     %d", self._total_commits)
        self.logger.info("=" * 70)


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Security Janitor v2.0 — Autonomous DevSecOps Agent (Dual-Tier)",
    )
    parser.add_argument(
        "--target", type=str, required=True,
        help="Path to the repository to monitor and fix",
    )
    parser.add_argument(
        "--watch", action="store_true",
        help="Enable continuous watch mode",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Report findings without patching or committing",
    )
    parser.add_argument(
        "--interval", type=int, default=30,
        help="Seconds between scans in watch mode (default: 30)",
    )
    parser.add_argument(
        "--no-commit", action="store_true",
        help="Patch files but do not create git branches/commits",
    )
    parser.add_argument(
        "--llm", type=str, default=None,
        choices=["local", "openai", "anthropic"],
        help="LLM backend for Tier 2 semantic patching",
    )
    parser.add_argument(
        "--llm-model", type=str, default=None,
        help="Override the LLM model (e.g., codellama:13b, gpt-4o)",
    )
    parser.add_argument(
        "--no-llm", action="store_true",
        help="Disable Tier 2 LLM patching entirely (regex-only mode)",
    )
    parser.add_argument(
        "--log-level", type=str, default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )

    args = parser.parse_args()

    # ── Logging Setup ────────────────────────────────────────────────
    log_level = getattr(logging, args.log_level)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(
        logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    )

    # File handler (janitor_strike.log)
    log_path = Path(args.target).resolve() / LOG_FILE
    file_handler = logging.FileHandler(str(log_path), encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)  # Always log DEBUG to file
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s │ %(levelname)-8s │ %(name)-24s │ %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    # ── Config ───────────────────────────────────────────────────────
    config = JanitorConfig(
        target_path=Path(args.target).resolve(),
        mode=RunMode.WATCH if args.watch else RunMode.SINGLE,
        dry_run=args.dry_run,
        watch_interval=args.interval,
        auto_commit=not args.no_commit,
        log_level=args.log_level,
        llm_mode=args.llm,
        llm_model=args.llm_model,
        enable_llm=not args.no_llm,
    )

    janitor = SecurityJanitor(config)
    janitor.run()


if __name__ == "__main__":
    main()
