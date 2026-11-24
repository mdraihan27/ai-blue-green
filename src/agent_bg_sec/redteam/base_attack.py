"""Abstract base class for all AI Red Team adversarial attack strategies."""

from abc import ABC, abstractmethod
from typing import List

from agent_bg_sec.core.models import (
    AgentManifest,
    AttackCategory,
    AttackPayload,
    AttackResult,
)
from agent_bg_sec.sandbox.agent_runner import GreenSandboxRunner, SandboxTurnOutcome


class BaseAttackStrategy(ABC):
    """Contract for generating context-aware payloads and evaluating attack outcomes."""

    @property
    @abstractmethod
    def category(self) -> AttackCategory:
        """Return the AttackCategory handled by this strategy."""

    @abstractmethod
    def generate_payloads(self, manifest: AgentManifest) -> List[AttackPayload]:
        """Synthesize adversarial test payloads tailored to the target AgentManifest."""

    @abstractmethod
    def evaluate_outcome(
        self,
        payload: AttackPayload,
        outcome: SandboxTurnOutcome,
        manifest: AgentManifest,
    ) -> AttackResult:
        """Analyze the Green sandbox telemetry and response to determine if the attack succeeded."""

    def execute_suite(
        self,
        manifest: AgentManifest,
        runner: GreenSandboxRunner,
    ) -> List[AttackResult]:
        """Generate and run all tailored payloads for this strategy against the Green agent."""
        payloads = self.generate_payloads(manifest)
        results: List[AttackResult] = []
        for payload in payloads:
            outcome = runner.execute_attack(payload)
            result = self.evaluate_outcome(payload, outcome, manifest)
            results.append(result)
        return results

