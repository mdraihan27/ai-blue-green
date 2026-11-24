"""Blue-Green traffic router and automated promotion/rollback state machine."""

from datetime import datetime, timezone
from typing import Optional, Tuple

from agent_bg_sec.core.models import (
    AgentManifest,
    DeploymentDecisionType,
    DeploymentSlot,
    DeploymentState,
    EnvironmentInstance,
    RiskAssessment,
)
from agent_bg_sec.deployment.state_store import BlueGreenStateStore


class BlueGreenTrafficController:
    """Manages Blue-Green staging deployment, promotion traffic cutover, and automatic rollback."""

    def __init__(self, state_store: BlueGreenStateStore) -> None:
        self.state_store = state_store

    def stage_in_green(self, manifest: AgentManifest) -> DeploymentState:
        """Deploy candidate AI agent version (N+1) into the idle Green environment."""
        current = self.state_store.load_state()
        green_instance = EnvironmentInstance(
            slot=DeploymentSlot.GREEN,
            agent_name=manifest.agent_name,
            version=manifest.version,
            source_path=manifest.source_path,
            commit_hash=manifest.commit_hash,
            security_score_pct=0.0,
            risk_score_pct=100.0,
            status="TESTING_IN_GREEN",
            receiving_traffic=False,
        )
        updated = DeploymentState(
            active_traffic_slot=current.active_traffic_slot,
            blue_env=current.blue_env,
            green_env=green_instance,
            total_promotions=current.total_promotions,
            total_rollbacks=current.total_rollbacks,
            history=current.history,
        )
        self.state_store.save_state(updated)
        return updated

    def apply_deployment_decision(
        self,
        manifest: AgentManifest,
        assessment: RiskAssessment,
    ) -> Tuple[DeploymentState, str]:
        """Promote Green -> Blue if RiskAssessment passed, or automatically roll back to Blue if failed."""
        current = self.state_store.load_state()
        now_iso = datetime.now(timezone.utc).isoformat()

        if assessment.passed_validation and assessment.decision == DeploymentDecisionType.PROMOTE_TO_BLUE:
            new_blue = EnvironmentInstance(
                slot=DeploymentSlot.BLUE,
                agent_name=manifest.agent_name,
                version=manifest.version,
                source_path=manifest.source_path,
                commit_hash=manifest.commit_hash,
                security_score_pct=assessment.security_score_pct,
                risk_score_pct=assessment.risk_score_pct,
                status="ACTIVE_PROMOTED",
                receiving_traffic=True,
                updated_at=now_iso,
            )
            promoted_green = EnvironmentInstance(
                slot=DeploymentSlot.GREEN,
                agent_name=manifest.agent_name,
                version=manifest.version,
                source_path=manifest.source_path,
                commit_hash=manifest.commit_hash,
                security_score_pct=assessment.security_score_pct,
                risk_score_pct=assessment.risk_score_pct,
                status="PROMOTED_TO_BLUE_IDLE",
                receiving_traffic=False,
                updated_at=now_iso,
            )
            event = {
                "timestamp": now_iso,
                "action": "PROMOTE_GREEN_TO_BLUE",
                "agent_name": manifest.agent_name,
                "version": manifest.version,
                "commit_hash": manifest.commit_hash,
                "security_score_pct": assessment.security_score_pct,
                "risk_score_pct": assessment.risk_score_pct,
                "previous_blue_agent": current.blue_env.agent_name,
                "previous_blue_version": current.blue_env.version,
            }
            history = list(current.history[-49:]) + [event]
            new_state = DeploymentState(
                active_traffic_slot=DeploymentSlot.BLUE,
                blue_env=new_blue,
                green_env=promoted_green,
                total_promotions=current.total_promotions + 1,
                total_rollbacks=current.total_rollbacks,
                history=history,
            )
            self.state_store.save_state(new_state)
            summary = (
                f"[TRAFFIC ROUTER] PROMOTED Green ({manifest.agent_name} v{manifest.version}, "
                f"Security Score={assessment.security_score_pct:.2f}%) -> Active Blue Production."
            )
            return new_state, summary

        # Otherwise: High Risk or Critical vulnerability -> Automatic Rollback to stable Blue
        rolled_back_green = EnvironmentInstance(
            slot=DeploymentSlot.GREEN,
            agent_name=manifest.agent_name,
            version=manifest.version,
            source_path=manifest.source_path,
            commit_hash=manifest.commit_hash,
            security_score_pct=assessment.security_score_pct,
            risk_score_pct=assessment.risk_score_pct,
            status="QUARANTINED_ROLLED_BACK",
            receiving_traffic=False,
            updated_at=now_iso,
        )
        event = {
            "timestamp": now_iso,
            "action": "AUTO_ROLLBACK_TO_BLUE",
            "rejected_green_agent": manifest.agent_name,
            "rejected_green_version": manifest.version,
            "commit_hash": manifest.commit_hash,
            "security_score_pct": assessment.security_score_pct,
            "risk_score_pct": assessment.risk_score_pct,
            "retained_blue_agent": current.blue_env.agent_name,
            "retained_blue_version": current.blue_env.version,
        }
        history = list(current.history[-49:]) + [event]
        new_state = DeploymentState(
            active_traffic_slot=DeploymentSlot.BLUE,
            blue_env=current.blue_env,
            green_env=rolled_back_green,
            total_promotions=current.total_promotions,
            total_rollbacks=current.total_rollbacks + 1,
            history=history,
        )
        self.state_store.save_state(new_state)
        summary = (
            f"[TRAFFIC ROUTER] AUTO-ROLLBACK TRIGGERED! Rejected Green ({manifest.agent_name} v{manifest.version}, "
            f"Security Score={assessment.security_score_pct:.2f}%, Risk Score={assessment.risk_score_pct:.2f}%). "
            f"Live traffic remains safely on Blue ({current.blue_env.agent_name} v{current.blue_env.version})."
        )
        return new_state, summary

    def manual_rollback(self, reason: Optional[str] = None) -> Tuple[DeploymentState, str]:
        """Force a manual rollback to the previous promoted Blue version from history if available."""
        current = self.state_store.load_state()
        now_iso = datetime.now(timezone.utc).isoformat()
        event = {
            "timestamp": now_iso,
            "action": "MANUAL_EMERGENCY_ROLLBACK",
            "reason": reason or "Operator requested manual rollback via CLI",
            "active_blue_agent": current.blue_env.agent_name,
        }
        history = list(current.history[-49:]) + [event]
        green_env = current.green_env
        if green_env:
            green_env = EnvironmentInstance(
                slot=DeploymentSlot.GREEN,
                agent_name=green_env.agent_name,
                version=green_env.version,
                source_path=green_env.source_path,
                commit_hash=green_env.commit_hash,
                security_score_pct=green_env.security_score_pct,
                risk_score_pct=green_env.risk_score_pct,
                status="MANUALLY_ROLLED_BACK",
                receiving_traffic=False,
                updated_at=now_iso,
            )
        new_state = DeploymentState(
            active_traffic_slot=DeploymentSlot.BLUE,
            blue_env=current.blue_env,
            green_env=green_env,
            total_promotions=current.total_promotions,
            total_rollbacks=current.total_rollbacks + 1,
            history=history,
        )
        self.state_store.save_state(new_state)
        return new_state, (
            f"[TRAFFIC ROUTER] Manual rollback executed. Production traffic pinned to stable Blue "
            f"({current.blue_env.agent_name} v{current.blue_env.version})."
        )

