"""
GIT OPS — Automated Git Branch/Commit Module
Part of the Trishula Security Janitor

Handles:
    - Creating fix branches (janitor-fix-{hash})
    - Staging patched files
    - Committing with structured messages
    - Returning to the original branch

Uses GitPython for all git operations.
"""

import logging
from pathlib import Path
from typing import Optional

try:
    from git import InvalidGitRepositoryError, Repo
    from git.exc import GitCommandError
    HAS_GIT = True
except ImportError:
    HAS_GIT = False

logger = logging.getLogger("Janitor.GitOps")


class GitOperator:
    """
    Manages git operations for the Security Janitor.

    Lifecycle:
        1. __init__() — discovers the repo root
        2. create_branch() — checks out a new branch
        3. stage_files() — adds patched files to the index
        4. commit() — commits with a structured message
        5. checkout_original() — returns to the starting branch
    """

    def __init__(self, target_path: Path):
        if not HAS_GIT:
            raise ImportError(
                "GitPython is not installed. Run: pip install gitpython"
            )

        self.target_path = target_path
        self.logger = logging.getLogger("Janitor.GitOps")

        try:
            self.repo = Repo(target_path, search_parent_directories=True)
        except InvalidGitRepositoryError:
            raise ValueError(
                f"No git repository found at or above: {target_path}"
            )

        self.repo_root = Path(self.repo.working_tree_dir)
        self._original_branch: Optional[str] = None
        self._current_branch: Optional[str] = None

        # Store the original branch/HEAD
        try:
            self._original_branch = self.repo.active_branch.name
        except TypeError:
            # Detached HEAD state
            self._original_branch = self.repo.head.commit.hexsha[:12]

        self.logger.debug(
            "Git initialized. Root: %s, Branch: %s",
            self.repo_root, self._original_branch,
        )

    @property
    def is_clean(self) -> bool:
        """Check if the working tree is clean."""
        return not self.repo.is_dirty(untracked_files=True)

    @property
    def current_branch(self) -> str:
        """Get the current branch name."""
        try:
            return self.repo.active_branch.name
        except TypeError:
            return self.repo.head.commit.hexsha[:12]

    def create_branch(self, branch_name: str) -> str:
        """Create and checkout a new branch from the current HEAD.

        Args:
            branch_name: Name for the new branch

        Returns:
            The branch name

        Raises:
            GitCommandError: If branch creation fails
        """
        self.logger.debug("Creating branch: %s", branch_name)
        stashed = False

        # Stash any uncommitted changes first (these are the patches)
        if self.repo.is_dirty():
            self.logger.debug("Stashing uncommitted changes...")
            self.repo.git.stash("push", "-m", f"janitor-autostash-{branch_name}")
            stashed = True

        try:
            # Create and checkout the new branch
            new_branch = self.repo.create_head(branch_name)
            new_branch.checkout()
            self._current_branch = branch_name
            self.logger.info("Checked out branch: %s", branch_name)

            # Pop the stash to restore patched files onto the new branch
            if stashed:
                self.logger.debug("Popping stash onto fix branch...")
                self.repo.git.stash("pop")

            return branch_name
        except GitCommandError as e:
            self.logger.error("Failed to create branch %s: %s", branch_name, e)
            raise

    def stage_files(self, file_paths: list[str]):
        """Stage specific files for commit.

        Args:
            file_paths: List of absolute or relative file paths to stage
        """
        for fp in file_paths:
            try:
                # Convert to relative path from repo root
                rel_path = Path(fp).resolve().relative_to(self.repo_root)
                self.repo.index.add([str(rel_path)])
                self.logger.debug("Staged: %s", rel_path)
            except ValueError:
                self.logger.warning("File not in repo: %s", fp)
            except Exception as e:
                self.logger.warning("Failed to stage %s: %s", fp, e)

        self.logger.info("Staged %d file(s)", len(file_paths))

    def commit(self, message: str) -> str:
        """Create a commit with the staged changes.

        Args:
            message: Commit message

        Returns:
            The commit SHA

        Raises:
            GitCommandError: If commit fails
        """
        try:
            commit = self.repo.index.commit(message)
            sha = commit.hexsha
            self.logger.info("Committed: %s", sha[:12])
            return sha
        except GitCommandError as e:
            self.logger.error("Commit failed: %s", e)
            raise

    def checkout_original(self):
        """Return to the original branch."""
        if self._original_branch:
            try:
                self.repo.git.checkout(self._original_branch)
                self._current_branch = self._original_branch
                self.logger.debug(
                    "Returned to original branch: %s", self._original_branch
                )
            except GitCommandError as e:
                self.logger.error(
                    "Failed to checkout original branch %s: %s",
                    self._original_branch, e,
                )

    def abort(self):
        """Abort current operations and return to a clean state."""
        self.logger.warning("Aborting git operations...")

        try:
            # Discard staged changes
            self.repo.git.reset("HEAD")
            # Checkout original branch
            if self._original_branch and self._current_branch != self._original_branch:
                self.repo.git.checkout(self._original_branch)
                # Delete the janitor branch if we created one
                if self._current_branch and self._current_branch.startswith("janitor-"):
                    try:
                        self.repo.git.branch("-D", self._current_branch)
                        self.logger.info("Deleted branch: %s", self._current_branch)
                    except GitCommandError:
                        pass
            # Pop stash if we stashed
            try:
                self.repo.git.stash("pop")
            except GitCommandError:
                pass
        except Exception as e:
            self.logger.error("Abort failed: %s", e)

    def get_status(self) -> dict:
        """Get the current git status."""
        return {
            "repo_root": str(self.repo_root),
            "original_branch": self._original_branch,
            "current_branch": self.current_branch,
            "is_clean": self.is_clean,
            "untracked": len(self.repo.untracked_files),
            "modified": len([
                item.a_path for item in self.repo.index.diff(None)
            ]),
        }
