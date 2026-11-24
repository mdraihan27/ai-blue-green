"""Renders comprehensive terminal scorecards and persists JSON/Markdown audit reports."""

import json
from pathlib import Path
from typing import Optional

from agent_bg_sec.core.logger import TerminalFormatter
from agent_bg_sec.core.models import (
    DeploymentDecisionType,
    DeploymentState,
    RiskAssessment,
)
from agent_bg_sec.redteam.orchestrator import RedTeamExecutionReport


class ValidationReportGenerator:
    """Produces rich terminal score tables and saves JSON audit reports."""

    def __init__(self, reports_dir: Path, formatter: Optional[TerminalFormatter] = None) -> None:
        self.reports_dir = reports_dir
        self.formatter = formatter or TerminalFormatter()

    def render_terminal_report(
        self,
        execution_report: RedTeamExecutionReport,
        assessment: RiskAssessment,
        deployment_summary: Optional[str] = None,
        deployment_state: Optional[DeploymentState] = None,
    ) -> str:
        """Format the full terminal scorecard including the percentage security score."""
        fmt = self.formatter
        manifest = execution_report.manifest
        metrics = assessment.metrics

        out = [
            fmt.banner(
                "AI RED TEAM SECURITY VALIDATION & BLUE-GREEN DEPLOYMENT REPORT",
                f"Target Agent: {manifest.agent_name} (v{manifest.version}) | Source: {manifest.source_type}",
            )
        ]

        # 1. Target Agent Profile
        out.append(fmt.section("1. Discovered Target Agent Profile (Green Sandbox)"))
        profile_rows = [
            ["Agent Name", manifest.agent_name],
            ["Version / Commit", f"{manifest.version} ({manifest.commit_hash[:8] if manifest.commit_hash else 'local'})"],
            ["Source Path / URL", manifest.repo_url or manifest.source_path],
            ["Domain", manifest.domain],
            ["Discovered Tools", ", ".join(t.name for t in manifest.tools)],
            ["Sensitive Assets", ", ".join(manifest.sensitive_assets)],
            ["Memory / RAG Store", "Enabled" if manifest.has_memory_store else "Stateless"],
        ]
        out.append(fmt.format_table(["Property", "Value"], profile_rows))

        # 2. Category-by-Category Red Team Breakdown
        out.append(fmt.section("2. AI Red Team Attack & Stress Suite Breakdown (8 Categories)"))
        cat_rows = []
        for cat_key, stats in metrics.category_breakdown.items():
            status_label = "SECURE (100%)" if stats["breached"] == 0 else f"VULNERABLE ({stats['breached']} breached)"
            cat_rows.append(
                [
                    cat_key.upper().replace("_", " "),
                    str(stats["total_tests"]),
                    str(stats["blocked"]),
                    str(stats["breached"]),
                    f"{stats['defense_score_pct']:.2f}%",
                    f"{stats['attack_success_rate_pct']:.2f}%",
                    status_label,
                ]
            )
        out.append(
            fmt.format_table(
                [
                    "Attack Category",
                    "Tests",
                    "Blocked",
                    "Breached",
                    "Defense Score (%)",
                    "Attack Success (%)",
                    "Status",
                ],
                cat_rows,
            )
        )

        # 3. Core Proposal Security Indicators
        out.append(fmt.section("3. Core Security & Operational Metrics (Proposal Section 7c)"))
        metric_rows = [
            ["Attack Success Rate (ASR)", f"{metrics.attack_success_rate_pct:.2f}%", "Lower is better (0.00% ideal)"],
            ["Policy Violation Rate (PVR)", f"{metrics.policy_violation_rate_pct:.2f}%", "Lower is better (0.00% ideal)"],
            ["Tool Misuse Rate (TMR)", f"{metrics.tool_misuse_rate_pct:.2f}%", "Lower is better (0.00% ideal)"],
            ["Sensitive Data Leakage Rate (SDLR)", f"{metrics.sensitive_data_leakage_rate_pct:.2f}%", "Lower is better (0.00% ideal)"],
            ["Task Completion Success (TCS)", f"{metrics.task_completion_success_pct:.2f}%", "Higher is better (100.00% ideal)"],
            ["Average Response Time (RT)", f"{metrics.avg_response_time_ms:.2f} ms", f"Latency Penalty: {metrics.response_time_penalty_pct:.2f}%"],
            ["Critical Vulnerabilities", str(metrics.critical_vulnerabilities_count), "Must be 0 for production promotion"],
        ]
        out.append(fmt.format_table(["Security Indicator", "Measured Value", "Target Benchmark"], metric_rows))

        # 4. Final Percentage Score & Deployment Readiness Verdict
        out.append(fmt.section("4. Final Percentage Security Score & Validation Verdict"))
        score_color = fmt.GREEN if assessment.passed_validation else fmt.RED
        verdict_label = (
            "APPROVED FOR PRODUCTION DEPLOYMENT"
            if assessment.passed_validation
            else "REJECTED - DO NOT DEPLOY (HIGH SECURITY RISK)"
        )
        score_box = [
            ["OVERALL SECURITY VALIDATION SCORE (%)", f"{assessment.security_score_pct:.2f}% (Minimum Required: {assessment.security_threshold_pct:.2f}%)"],
            ["WEIGHTED CYBERSECURITY RISK SCORE (%)", f"{assessment.risk_score_pct:.2f}% (Maximum Allowed: {assessment.risk_threshold_pct:.2f}%)"],
            ["RISK SEVERITY LEVEL", assessment.risk_level.value],
            ["VALIDATION OUTCOME", "PASSED" if assessment.passed_validation else "FAILED"],
            ["DEPLOYMENT READINESS VERDICT", verdict_label],
        ]
        out.append(fmt.colorize(fmt.format_table(["Final Assessment Metric", "Result"], score_box), score_color + fmt.BOLD))
        out.append(f"\nAssessment Summary: {assessment.decision_reason}")

        out.append(fmt.section("5. Actionable Security Recommendations"))
        for idx, rec in enumerate(assessment.recommendations, start=1):
            out.append(f"  {idx}. {rec}")

        return "\n".join(out)

    def save_json_report(
        self,
        execution_report: RedTeamExecutionReport,
        assessment: RiskAssessment,
        custom_output_path: Optional[Path] = None,
    ) -> Path:
        """Persist complete machine-readable validation report to JSON."""
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        target_path = custom_output_path or (
            self.reports_dir / f"report_{assessment.agent_name}_{assessment.agent_version}.json"
        )
        payload = {
            "agent_manifest": execution_report.manifest.to_dict(),
            "risk_assessment": assessment.to_dict(),
            "attack_results": [
                {
                    "attack_id": r.attack_id,
                    "category": r.category.value,
                    "attack_name": r.attack_name,
                    "severity": r.severity.value,
                    "attack_succeeded": r.attack_succeeded,
                    "policy_violated": r.policy_violated,
                    "tool_misused": r.tool_misused,
                    "data_leaked": r.data_leaked,
                    "memory_poisoned": r.memory_poisoned,
                    "privilege_escalated": r.privilege_escalated,
                    "response_time_ms": r.response_time_ms,
                    "evidence": r.evidence,
                }
                for r in execution_report.attack_results
            ],
        }
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return target_path

