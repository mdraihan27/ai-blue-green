"""Continuous GitHub repository watcher that detects new pushes/commits and triggers validation."""

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, List, Optional

from agent_bg_sec.core.exceptions import AgentSecError, GitOperationError
from agent_bg_sec.core.logger import AuditLogger
from agent_bg_sec.core.models import AgentManifest, RiskAssessment
from agent_bg_sec.ingestion.github_ingestor import GitHubRepoIngestor


@dataclass(frozen=True)
class WatchCycleEvent:
    """Record of a single continuous watcher poll or triggered validation run."""

    cycle_number: int
    checked_at: str
    detected_commit: Optional[str]
    triggered_test: bool
    security_score_pct: Optional[float] = None
    risk_score_pct: Optional[float] = None
    decision: Optional[str] = None
    error_message: Optional[str] = None


class ContinuousGitHubWatcher:
    """Polls a GitHub repository for new pushes/commits and runs automated Green validation."""

    def __init__(
        self,
        github_ingestor: GitHubRepoIngestor,
        on_new_commit_callback: Callable[[AgentManifest], RiskAssessment],
        logger: AuditLogger,
        poll_interval_seconds: int = 30,
    ) -> None:
        if poll_interval_seconds <= 0:
            raise ValueError("poll_interval_seconds must be positive.")
        self.github_ingestor = github_ingestor
        self.on_new_commit_callback = on_new_commit_callback
        self.logger = logger
        self.poll_interval_seconds = poll_interval_seconds
        self.last_tested_commit: Optional[str] = None
        self.events: List[WatchCycleEvent] = []

    def check_once(self, cycle_number: int = 1, force_initial: bool = False) -> WatchCycleEvent:
        """Perform a single remote commit check and run validation if a new push arrived."""
        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            remote_commit = self.github_ingestor.get_remote_head_commit()
        except GitOperationError as exc:
            self.logger.warning(
                f"[Cycle #{cycle_number}] Transient Git poll failure: {exc.message}"
            )
            event = WatchCycleEvent(
                cycle_number=cycle_number,
                checked_at=now_iso,
                detected_commit=None,
                triggered_test=False,
                error_message=exc.message,
            )
            self.events.append(event)
            return event

        is_new_push = (
            force_initial
            or self.last_tested_commit is None
            or remote_commit != self.last_tested_commit
        )

        if not is_new_push:
            self.logger.info(
                f"[Cycle #{cycle_number}] No new push detected on '{self.github_ingestor.repo_url}' "
                f"(HEAD remains {remote_commit[:8]})."
            )
            event = WatchCycleEvent(
                cycle_number=cycle_number,
                checked_at=now_iso,
                detected_commit=remote_commit,
                triggered_test=False,
            )
            self.events.append(event)
            return event

        if self.last_tested_commit is None:
            self.logger.info(
                f"[Cycle #{cycle_number}] Initial commit detected ({remote_commit[:8]}). "
                "Fetching into Green environment and starting AI Red Team validation..."
            )
        else:
            self.logger.info(
                f"[Cycle #{cycle_number}] NEW PUSH DETECTED ({self.last_tested_commit[:8]} -> {remote_commit[:8]})! "
                "Fetching into Green environment and starting AI Red Team validation..."
            )

        try:
            manifest = self.github_ingestor.ingest()
            assessment = self.on_new_commit_callback(manifest)
            self.last_tested_commit = remote_commit
            event = WatchCycleEvent(
                cycle_number=cycle_number,
                checked_at=now_iso,
                detected_commit=remote_commit,
                triggered_test=True,
                security_score_pct=assessment.security_score_pct,
                risk_score_pct=assessment.risk_score_pct,
                decision=assessment.decision.value,
            )
            self.events.append(event)
            return event
        except AgentSecError as exc:
            self.logger.error(
                f"[Cycle #{cycle_number}] Validation error on commit {remote_commit[:8]}: {exc.message}"
            )
            event = WatchCycleEvent(
                cycle_number=cycle_number,
                checked_at=now_iso,
                detected_commit=remote_commit,
                triggered_test=True,
                error_message=exc.message,
            )
            self.events.append(event)
            return event

    def watch_loop(self, max_cycles: Optional[int] = None) -> List[WatchCycleEvent]:
        """Run continuous monitoring loop until interrupted by Ctrl+C or max_cycles is reached."""
        self.logger.info(
            f"Starting Continuous GitHub Push Watcher for '{self.github_ingestor.repo_url}' "
            f"(branch={self.github_ingestor.branch or 'default'}, poll_interval={self.poll_interval_seconds}s)."
        )
        cycle = 0
        try:
            while True:
                cycle += 1
                self.check_once(cycle_number=cycle, force_initial=(cycle == 1))
                if max_cycles is not None and cycle >= max_cycles:
                    self.logger.info(f"Completed requested {max_cycles} watch cycle(s).")
                    break
                time.sleep(self.poll_interval_seconds)
        except KeyboardInterrupt:
            self.logger.info("Continuous watcher stopped gracefully by user (SIGINT).")
        return self.events

