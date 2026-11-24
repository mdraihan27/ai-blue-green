"""Persistent state storage for Blue (active production) and Green (staging) environments."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from agent_bg_sec.core.exceptions import DeploymentStateError
from agent_bg_sec.core.models import (
    DeploymentSlot,
    DeploymentState,
    EnvironmentInstance,
)


class BlueGreenStateStore:
    """Safely persists and loads the Blue-Green deployment cluster state as atomic JSON."""

    def __init__(self, state_file_path: Path) -> None:
        self.state_file_path = state_file_path

    def load_state(self) -> DeploymentState:
        """Load the current Blue-Green state or initialize a default stable Blue environment."""
        if not self.state_file_path.is_file():
            default_state = self._create_initial_state()
            self.save_state(default_state)
            return default_state

        try:
            raw = json.loads(self.state_file_path.read_text(encoding="utf-8"))
            blue_raw = raw["blue_env"]
            green_raw = raw.get("green_env")
            return DeploymentState(
                active_traffic_slot=DeploymentSlot(raw.get("active_traffic_slot", "BLUE")),
                blue_env=self._parse_instance(blue_raw),
                green_env=self._parse_instance(green_raw) if green_raw else None,
                total_promotions=int(raw.get("total_promotions", 0)),
                total_rollbacks=int(raw.get("total_rollbacks", 0)),
                history=list(raw.get("history", [])),
            )
        except (OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
            # Recover gracefully if state file was corrupted
            default_state = self._create_initial_state()
            self.save_state(default_state)
            return default_state

    def save_state(self, state: DeploymentState) -> None:
        """Atomically persist the Blue-Green state to disk."""
        try:
            self.state_file_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self.state_file_path.with_suffix(".tmp")
            tmp_path.write_text(json.dumps(state.to_dict(), indent=2), encoding="utf-8")
            tmp_path.replace(self.state_file_path)
        except OSError as exc:
            raise DeploymentStateError(
                f"Failed to persist Blue-Green deployment state to '{self.state_file_path}': {exc}",
                cause=exc,
            ) from exc

    @staticmethod
    def _create_initial_state() -> DeploymentState:
        initial_blue = EnvironmentInstance(
            slot=DeploymentSlot.BLUE,
            agent_name="baseline_production_agent",
            version="1.0.0-stable",
            source_path="production/baseline",
            commit_hash="00000000",
            security_score_pct=100.0,
            risk_score_pct=0.0,
            status="ACTIVE",
            receiving_traffic=True,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
        return DeploymentState(
            active_traffic_slot=DeploymentSlot.BLUE,
            blue_env=initial_blue,
            green_env=None,
            total_promotions=0,
            total_rollbacks=0,
            history=[],
        )

    @staticmethod
    def _parse_instance(data: Dict[str, Any]) -> Optional[EnvironmentInstance]:
        if not data:
            return None
        return EnvironmentInstance(
            slot=DeploymentSlot(data["slot"]),
            agent_name=str(data["agent_name"]),
            version=str(data["version"]),
            source_path=str(data["source_path"]),
            commit_hash=data.get("commit_hash"),
            security_score_pct=float(data["security_score_pct"]),
            risk_score_pct=float(data["risk_score_pct"]),
            status=str(data["status"]),
            receiving_traffic=bool(data["receiving_traffic"]),
            updated_at=str(data.get("updated_at", datetime.now(timezone.utc).isoformat())),
        )

