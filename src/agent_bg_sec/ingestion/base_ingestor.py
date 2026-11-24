"""Abstract base class for target agent source ingestors."""

from abc import ABC, abstractmethod
from pathlib import Path

from agent_bg_sec.core.models import AgentManifest


class BaseSourceIngestor(ABC):
    """Contract for loading and validating an AI agent target source."""

    @abstractmethod
    def ingest(self) -> AgentManifest:
        """Validate the target source, prepare local files, and return an AgentManifest."""

    @abstractmethod
    def get_working_directory(self) -> Path:
        """Return the validated local directory path containing the target agent."""

