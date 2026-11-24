"""Orchestrates all 6 AI Red Team attack strategies and benign task checks against the Green environment."""

from dataclasses import dataclass, replace
from typing import List, Optional

from agent_bg_sec.core.models import AgentManifest, AttackPayload, AttackResult, BenignTaskResult
from agent_bg_sec.core.openrouter_client import OpenRouterClient
from agent_bg_sec.redteam.base_attack import BaseAttackStrategy
from agent_bg_sec.redteam.strategies.data_leakage import SensitiveDataLeakageStrategy
from agent_bg_sec.redteam.strategies.jailbreak import JailbreakStrategy
from agent_bg_sec.redteam.strategies.memory_poisoning import MemoryPoisoningStrategy
from agent_bg_sec.redteam.strategies.privilege_escalation import PrivilegeEscalationStrategy
from agent_bg_sec.redteam.strategies.prompt_injection import PromptInjectionStrategy
from agent_bg_sec.redteam.strategies.sql_query_injection import SqlAndQueryInjectionStrategy
from agent_bg_sec.redteam.strategies.stress_test import StressAndDosResilienceStrategy
from agent_bg_sec.redteam.strategies.tool_abuse import ToolAbuseStrategy
from agent_bg_sec.redteam.task_evaluator import BenignTaskEvaluator
from agent_bg_sec.sandbox.agent_runner import GreenSandboxRunner


@dataclass(frozen=True)
class RedTeamExecutionReport:
    """Combined output from running all Red Team strategies and benign functional tasks."""

    manifest: AgentManifest
    attack_results: List[AttackResult]
    benign_results: List[BenignTaskResult]


class RedTeamOrchestrator:
    """Coordinates context-aware attack synthesis and execution across all 6 threat categories."""

    def __init__(
        self,
        strategies: Optional[List[BaseAttackStrategy]] = None,
        task_evaluator: Optional[BenignTaskEvaluator] = None,
        sandbox_timeout_seconds: float = 5.0,
        openrouter_client: Optional[OpenRouterClient] = None,
    ) -> None:
        self.strategies: List[BaseAttackStrategy] = strategies or [
            PromptInjectionStrategy(),
            ToolAbuseStrategy(),
            MemoryPoisoningStrategy(),
            SensitiveDataLeakageStrategy(),
            JailbreakStrategy(),
            PrivilegeEscalationStrategy(),
            SqlAndQueryInjectionStrategy(),
            StressAndDosResilienceStrategy(),
        ]
        self.task_evaluator = task_evaluator or BenignTaskEvaluator()
        self.sandbox_timeout_seconds = sandbox_timeout_seconds
        self.openrouter_client = openrouter_client or OpenRouterClient()

    def run_validation_suite(self, manifest: AgentManifest) -> RedTeamExecutionReport:
        """Deploy target agent into the Green sandbox and execute all Red Team and benign suites."""
        runner = GreenSandboxRunner(
            manifest=manifest,
            timeout_seconds=self.sandbox_timeout_seconds,
        )
        all_attack_results: List[AttackResult] = []
        tool_names = [t.name for t in manifest.tools]
        for strategy in self.strategies:
            payloads = strategy.generate_payloads(manifest)
            for payload in payloads:
                active_payload: AttackPayload = payload
                if self.openrouter_client.is_configured:
                    mutated_prompt = self.openrouter_client.synthesize_contextual_attack(
                        agent_name=manifest.agent_name,
                        domain=manifest.domain,
                        category_name=payload.category.value,
                        tool_names=tool_names,
                        fallback_prompt=payload.prompt,
                    )
                    active_payload = replace(payload, prompt=mutated_prompt)
                outcome = runner.execute_attack(active_payload)
                result = strategy.evaluate_outcome(active_payload, outcome, manifest)
                all_attack_results.append(result)

        benign_results = self.task_evaluator.evaluate_tasks(manifest, runner)
        return RedTeamExecutionReport(
            manifest=manifest,
            attack_results=all_attack_results,
            benign_results=benign_results,
        )

