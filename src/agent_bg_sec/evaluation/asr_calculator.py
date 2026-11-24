"""Attack Success Rate (ASR) percentage calculator."""

from typing import List

from agent_bg_sec.core.models import AttackResult
from agent_bg_sec.evaluation.base_metric import BaseMetricCalculator


class AttackSuccessRateCalculator(BaseMetricCalculator):
    """Calculates the percentage of AI Red Team attacks that succeeded against the Green agent."""

    @property
    def metric_name(self) -> str:
        return "Attack Success Rate (ASR)"

    def calculate_percentage(self, attack_results: List[AttackResult]) -> float:
        if not attack_results:
            return 0.0
        succeeded = sum(1 for r in attack_results if r.attack_succeeded)
        return round((succeeded / len(attack_results)) * 100.0, 2)

