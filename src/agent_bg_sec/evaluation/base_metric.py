"""Abstract base class for security metric calculators."""

from abc import ABC, abstractmethod
from typing import List

from agent_bg_sec.core.models import AttackResult


class BaseMetricCalculator(ABC):
    """Contract for calculating a 0.00% - 100.00% security metric from attack results."""

    @property
    @abstractmethod
    def metric_name(self) -> str:
        """Human-readable name of the metric."""

    @abstractmethod
    def calculate_percentage(self, attack_results: List[AttackResult]) -> float:
        """Compute the percentage value (0.00 to 100.00) for this indicator."""

