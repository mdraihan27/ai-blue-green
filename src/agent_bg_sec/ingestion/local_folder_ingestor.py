"""Local directory ingestor with defensive path, permission, and content validation."""

import os
from pathlib import Path
from typing import Optional

from agent_bg_sec.core.env_loader import DotEnvLoader
from agent_bg_sec.core.exceptions import IngestionError
from agent_bg_sec.core.models import AgentManifest
from agent_bg_sec.ingestion.ast_introspector import AgentASTIntrospector
from agent_bg_sec.ingestion.base_ingestor import BaseSourceIngestor


class LocalFolderIngestor(BaseSourceIngestor):
    """Validates and ingests an AI agent from a local filesystem path."""

    def __init__(
        self,
        folder_path: str | Path,
        introspector: Optional[AgentASTIntrospector] = None,
    ) -> None:
        self.raw_path = str(folder_path).strip()
        self.introspector = introspector or AgentASTIntrospector()
        self._resolved_dir: Optional[Path] = None

    def get_working_directory(self) -> Path:
        if self._resolved_dir is None:
            self._resolved_dir = self._validate_path()
        return self._resolved_dir

    def ingest(self) -> AgentManifest:
        target_dir = self.get_working_directory()
        DotEnvLoader.load_env_files(extra_paths=[target_dir])
        return self.introspector.inspect_directory(
            target_dir=target_dir,
            source_type="local_folder",
        )

    def _validate_path(self) -> Path:
        if not self.raw_path:
            raise IngestionError(
                "Target folder path cannot be empty.",
                recovery_hint="Provide a valid directory path or Python agent file path.",
            )

        try:
            candidate = Path(self.raw_path).expanduser().resolve()
        except (OSError, RuntimeError) as exc:
            raise IngestionError(
                f"Cannot resolve target path '{self.raw_path}': {exc}",
                cause=exc,
            ) from exc

        if not candidate.exists():
            raise IngestionError(
                f"Target path does not exist: '{candidate}'",
                recovery_hint="Double-check the folder path and ensure it exists on disk.",
            )

        # If user passed a single .py or manifest file, use its parent directory
        if candidate.is_file():
            if candidate.suffix == ".py" or candidate.name.endswith("manifest.json"):
                candidate = candidate.parent
            else:
                raise IngestionError(
                    f"Target path '{candidate}' is a file, not an agent directory or Python script.",
                    recovery_hint="Pass the directory containing the AI agent or its main .py file.",
                )

        if not candidate.is_dir():
            raise IngestionError(f"Target path '{candidate}' is not a directory.")

        if not os.access(candidate, os.R_OK | os.X_OK):
            raise IngestionError(
                f"Insufficient permissions to read target directory: '{candidate}'",
                recovery_hint="Grant read/execute permissions (`chmod +rx`) on the target folder.",
            )

        try:
            entries = list(candidate.iterdir())
        except OSError as exc:
            raise IngestionError(
                f"Failed to list contents of directory '{candidate}': {exc}",
                cause=exc,
            ) from exc

        if not entries:
            raise IngestionError(
                f"Target directory '{candidate}' is empty.",
                recovery_hint="Ensure the folder contains the AI agent source code.",
            )

        return candidate

