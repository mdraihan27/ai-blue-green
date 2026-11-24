"""High-level application controller coordinating ingestion, Red Team testing, scoring, and Blue-Green routing."""

from pathlib import Path
from typing import Optional, Tuple

from agent_bg_sec.core.config import AppConfig
from agent_bg_sec.core.logger import AuditLogger, TerminalFormatter
from agent_bg_sec.core.models import AgentManifest, DeploymentState, RiskAssessment
from agent_bg_sec.core.openrouter_client import OpenRouterClient
from agent_bg_sec.deployment.state_store import BlueGreenStateStore
from agent_bg_sec.deployment.traffic_router import BlueGreenTrafficController
from agent_bg_sec.evaluation.risk_scorer import SecurityRiskScorer
from agent_bg_sec.monitoring.prometheus_exporter import PrometheusMetricsExporter
from agent_bg_sec.monitoring.report_generator import ValidationReportGenerator
from agent_bg_sec.redteam.orchestrator import RedTeamExecutionReport, RedTeamOrchestrator


class ValidationPipelineController:
    """Executes the end-to-end Green staging -> Red Team attack -> Risk Score -> Blue-Green decision workflow."""

    def __init__(
        self,
        config: AppConfig,
        logger: Optional[AuditLogger] = None,
        formatter: Optional[TerminalFormatter] = None,
    ) -> None:
        self.config = config
        self.config.ensure_directories()
        self.formatter = formatter or TerminalFormatter()
        self.logger = logger or AuditLogger(
            log_file=self.config.workspace_dir / "audit.jsonl"
        )
        self.openrouter_client = OpenRouterClient(
            api_key=config.openrouter_api_key,
            model=config.openrouter_model,
            base_url=config.openrouter_base_url,
        )
        self.orchestrator = RedTeamOrchestrator(
            sandbox_timeout_seconds=config.sandbox_timeout_seconds,
            openrouter_client=self.openrouter_client,
        )
        self.scorer = SecurityRiskScorer(config)
        self.state_store = BlueGreenStateStore(config.state_file_path)
        self.traffic_controller = BlueGreenTrafficController(self.state_store)
        self.report_generator = ValidationReportGenerator(
            reports_dir=config.reports_dir,
            formatter=self.formatter,
        )
        self.prometheus_exporter = PrometheusMetricsExporter(
            export_path=config.metrics_export_path
        )

    def validate_and_evaluate(
        self,
        manifest: AgentManifest,
        apply_blue_green_deployment: bool = True,
        output_json_path: Optional[Path] = None,
        print_report: bool = True,
    ) -> Tuple[RedTeamExecutionReport, RiskAssessment, Optional[DeploymentState]]:
        """Run the full AI Red Team suite against a loaded AgentManifest and optionally promote/rollback."""
        self.logger.info(
            f"Deploying target agent '{manifest.agent_name}' (v{manifest.version}) into isolated GREEN environment..."
        )
        if apply_blue_green_deployment:
            self.traffic_controller.stage_in_green(manifest)

        self.logger.info(
            f"Launching AI Red Team attack suites across 6 threat domains against '{manifest.agent_name}'..."
        )
        execution_report = self.orchestrator.run_validation_suite(manifest)
        assessment = self.scorer.evaluate(
            execution_report,
            enforce_deployment_gate=apply_blue_green_deployment,
        )

        deployment_state: Optional[DeploymentState] = None
        deployment_summary: Optional[str] = None
        if apply_blue_green_deployment:
            deployment_state, deployment_summary = (
                self.traffic_controller.apply_deployment_decision(manifest, assessment)
            )
            self.prometheus_exporter.export_metrics(assessment, deployment_state)
        else:
            deployment_state = self.state_store.load_state()
            self.prometheus_exporter.export_metrics(assessment, deployment_state)

        saved_report = self.report_generator.save_json_report(
            execution_report=execution_report,
            assessment=assessment,
            custom_output_path=output_json_path,
        )

        if print_report:
            rendered = self.report_generator.render_terminal_report(
                execution_report=execution_report,
                assessment=assessment,
                deployment_summary=deployment_summary,
                deployment_state=deployment_state,
            )
            print(rendered)
            self.logger.info(f"Saved detailed JSON validation report to: {saved_report}")

        if assessment.passed_validation:
            self.logger.success(
                f"Agent '{manifest.agent_name}' PASSED validation with Security Score: "
                f"{assessment.security_score_pct:.2f}% (Risk Score: {assessment.risk_score_pct:.2f}%)."
            )
        else:
            self.logger.warning(
                f"Agent '{manifest.agent_name}' FAILED validation with Security Score: "
                f"{assessment.security_score_pct:.2f}% (Risk Score: {assessment.risk_score_pct:.2f}%)."
            )

        return execution_report, assessment, deployment_state

