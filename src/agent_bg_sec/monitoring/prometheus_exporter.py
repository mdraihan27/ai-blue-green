"""Prometheus metrics exporter for Grafana dashboards and MLOps monitoring."""

from pathlib import Path

from agent_bg_sec.core.models import DeploymentState, RiskAssessment


class PrometheusMetricsExporter:
    """Exports AI Red Team security validation and Blue-Green deployment metrics in Prometheus text format."""

    def __init__(self, export_path: Path) -> None:
        self.export_path = export_path

    def export_metrics(
        self,
        assessment: RiskAssessment,
        deployment_state: DeploymentState,
    ) -> str:
        """Format and write Prometheus metrics to disk."""
        m = assessment.metrics
        labels = f'agent="{assessment.agent_name}",version="{assessment.agent_version}"'
        lines = [
            "# HELP ai_agent_security_score_percent Overall AI Agent Security Validation Score (0-100%)",
            "# TYPE ai_agent_security_score_percent gauge",
            f"ai_agent_security_score_percent{{{labels}}} {assessment.security_score_pct:.2f}",
            "# HELP ai_agent_risk_score_percent Weighted AI Agent Risk Score (0-100%)",
            "# TYPE ai_agent_risk_score_percent gauge",
            f"ai_agent_risk_score_percent{{{labels}}} {assessment.risk_score_pct:.2f}",
            "# HELP ai_agent_attack_success_rate_percent Attack Success Rate ASR (0-100%)",
            "# TYPE ai_agent_attack_success_rate_percent gauge",
            f"ai_agent_attack_success_rate_percent{{{labels}}} {m.attack_success_rate_pct:.2f}",
            "# HELP ai_agent_policy_violation_rate_percent Policy Violation Rate PVR (0-100%)",
            "# TYPE ai_agent_policy_violation_rate_percent gauge",
            f"ai_agent_policy_violation_rate_percent{{{labels}}} {m.policy_violation_rate_pct:.2f}",
            "# HELP ai_agent_tool_misuse_rate_percent Tool Misuse Rate TMR (0-100%)",
            "# TYPE ai_agent_tool_misuse_rate_percent gauge",
            f"ai_agent_tool_misuse_rate_percent{{{labels}}} {m.tool_misuse_rate_pct:.2f}",
            "# HELP ai_agent_sensitive_data_leakage_rate_percent Sensitive Data Leakage Rate SDLR (0-100%)",
            "# TYPE ai_agent_sensitive_data_leakage_rate_percent gauge",
            f"ai_agent_sensitive_data_leakage_rate_percent{{{labels}}} {m.sensitive_data_leakage_rate_pct:.2f}",
            "# HELP ai_agent_task_completion_success_percent Benign Task Completion Success TCS (0-100%)",
            "# TYPE ai_agent_task_completion_success_percent gauge",
            f"ai_agent_task_completion_success_percent{{{labels}}} {m.task_completion_success_pct:.2f}",
            "# HELP ai_agent_avg_response_time_ms Average Agent Response Latency in ms",
            "# TYPE ai_agent_avg_response_time_ms gauge",
            f"ai_agent_avg_response_time_ms{{{labels}}} {m.avg_response_time_ms:.2f}",
            "# HELP blue_green_promotions_total Total successful Green-to-Blue promotions",
            "# TYPE blue_green_promotions_total counter",
            f"blue_green_promotions_total {deployment_state.total_promotions}",
            "# HELP blue_green_rollbacks_total Total automated or manual rollbacks to Blue",
            "# TYPE blue_green_rollbacks_total counter",
            f"blue_green_rollbacks_total {deployment_state.total_rollbacks}",
        ]
        payload = "\n".join(lines) + "\n"
        try:
            self.export_path.parent.mkdir(parents=True, exist_ok=True)
            self.export_path.write_text(payload, encoding="utf-8")
        except OSError:
            pass
        return payload

