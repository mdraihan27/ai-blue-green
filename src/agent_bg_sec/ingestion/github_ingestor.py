"""GitHub repository cloner and remote commit resolver with strict timeout and URL validation."""

import hashlib
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from agent_bg_sec.core.exceptions import GitOperationError
from agent_bg_sec.core.models import AgentManifest
from agent_bg_sec.ingestion.ast_introspector import AgentASTIntrospector
from agent_bg_sec.ingestion.base_ingestor import BaseSourceIngestor


class GitHubRepoIngestor(BaseSourceIngestor):
    """Clones or updates a GitHub repository (or local bare/git repo URL) and introspects the agent."""

    GITHUB_URL_PATTERN = re.compile(
        r"^(https?://(www\.)?github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(\.git)?/?$"
        r"|git@github\.com:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(\.git)?$"
        r"|file:///.+"
        r"|/[A-Za-z0-9_./-]+)$"
    )

    def __init__(
        self,
        repo_url: str,
        clones_base_dir: Path,
        branch: Optional[str] = None,
        subpath: Optional[str] = None,
        clone_timeout_seconds: int = 60,
        introspector: Optional[AgentASTIntrospector] = None,
    ) -> None:
        self.repo_url = repo_url.strip()
        self.clones_base_dir = clones_base_dir
        self.branch = branch.strip() if branch and branch.strip() else None
        self.subpath = subpath.strip().strip("/") if subpath and subpath.strip() else None
        self.clone_timeout_seconds = clone_timeout_seconds
        self.introspector = introspector or AgentASTIntrospector()
        self._checkout_dir: Optional[Path] = None
        self._commit_hash: Optional[str] = None

    def validate_url(self) -> None:
        """Validate GitHub repository URL or local git repository path."""
        if not self.repo_url:
            raise GitOperationError(
                "Repository URL cannot be empty.",
                recovery_hint="Pass a valid GitHub URL such as https://github.com/owner/repo.git",
            )

        # Allow local git repositories for offline testing/CI in addition to GitHub URLs
        local_candidate = Path(self.repo_url)
        if local_candidate.exists() and (
            (local_candidate / ".git").exists() or (local_candidate / "HEAD").exists()
        ):
            return

        if not self.GITHUB_URL_PATTERN.match(self.repo_url):
            raise GitOperationError(
                f"Invalid GitHub repository URL: '{self.repo_url}'",
                recovery_hint="Use format 'https://github.com/<owner>/<repo>' or 'git@github.com:<owner>/<repo>.git'.",
            )

    def get_remote_head_commit(self) -> str:
        """Query the remote repository's latest commit SHA without a full clone (`git ls-remote`)."""
        self.validate_url()
        ref = f"refs/heads/{self.branch}" if self.branch else "HEAD"
        cmd = ["git", "ls-remote", self.repo_url, ref]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.clone_timeout_seconds,
                check=False,
                env={"GIT_TERMINAL_PROMPT": "0", "PATH": "/usr/bin:/bin:/usr/local/bin"},
            )
        except subprocess.TimeoutExpired as exc:
            raise GitOperationError(
                f"Timed out querying remote commit for '{self.repo_url}' after {self.clone_timeout_seconds}s.",
                cause=exc,
            ) from exc
        except OSError as exc:
            raise GitOperationError(
                f"Failed to execute git ls-remote: {exc}",
                cause=exc,
            ) from exc

        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            raise GitOperationError(
                f"Unable to reach repository '{self.repo_url}': {stderr or 'git ls-remote failed'}",
                recovery_hint="Check that the repository exists, is public (or credentials are configured), and the branch name is valid.",
            )

        output = (proc.stdout or "").strip()
        if not output:
            raise GitOperationError(
                f"Remote reference '{ref}' not found in '{self.repo_url}'.",
                recovery_hint="Verify that the specified branch exists on the remote repository.",
            )

        commit_sha = output.split()[0].strip()
        return commit_sha

    def clone_or_refresh(self) -> Path:
        """Clone the repository into an isolated workspace directory (or refresh if already cloned)."""
        self.validate_url()
        self.clones_base_dir.mkdir(parents=True, exist_ok=True)

        url_hash = hashlib.sha256(
            f"{self.repo_url}:{self.branch or 'default'}".encode("utf-8")
        ).hexdigest()[:12]
        repo_slug = self._extract_repo_slug()
        dest_dir = self.clones_base_dir / f"{repo_slug}_{url_hash}"

        if dest_dir.exists():
            shutil.rmtree(dest_dir, ignore_errors=True)

        cmd = ["git", "clone", "--depth", "1"]
        if self.branch:
            cmd.extend(["--branch", self.branch])
        cmd.extend([self.repo_url, str(dest_dir)])

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.clone_timeout_seconds,
                check=False,
                env={"GIT_TERMINAL_PROMPT": "0", "PATH": "/usr/bin:/bin:/usr/local/bin"},
            )
        except subprocess.TimeoutExpired as exc:
            shutil.rmtree(dest_dir, ignore_errors=True)
            raise GitOperationError(
                f"Git clone timed out after {self.clone_timeout_seconds}s for '{self.repo_url}'.",
                cause=exc,
            ) from exc
        except OSError as exc:
            raise GitOperationError(f"Git execution error: {exc}", cause=exc) from exc

        if proc.returncode != 0:
            shutil.rmtree(dest_dir, ignore_errors=True)
            stderr = (proc.stderr or "").strip()
            raise GitOperationError(
                f"Git clone failed for '{self.repo_url}': {stderr}",
                recovery_hint="Verify the repository URL, branch name, and internet connection.",
            )

        self._commit_hash = self._read_local_head_commit(dest_dir)
        target_dir = dest_dir / self.subpath if self.subpath else dest_dir
        if not target_dir.exists() or not target_dir.is_dir():
            raise GitOperationError(
                f"Subpath '{self.subpath}' does not exist inside cloned repository '{self.repo_url}'."
            )

        self._checkout_dir = target_dir
        return target_dir

    def get_working_directory(self) -> Path:
        if self._checkout_dir is None or not self._checkout_dir.exists():
            return self.clone_or_refresh()
        return self._checkout_dir

    def ingest(self) -> AgentManifest:
        work_dir = self.clone_or_refresh()
        return self.introspector.inspect_directory(
            target_dir=work_dir,
            source_type="github_repo",
            repo_url=self.repo_url,
            commit_hash=self._commit_hash,
        )

    def _extract_repo_slug(self) -> str:
        cleaned = self.repo_url.rstrip("/")
        if cleaned.endswith(".git"):
            cleaned = cleaned[:-4]
        name = cleaned.split("/")[-1].split(":")[-1]
        safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
        return safe_name or "repo"

    def _read_local_head_commit(self, repo_dir: Path) -> Optional[str]:
        try:
            proc = subprocess.run(
                ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if proc.returncode == 0:
                return proc.stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            pass
        return None

