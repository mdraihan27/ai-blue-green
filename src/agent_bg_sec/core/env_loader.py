"""Automatic .env file loader supporting project root and target agent directories."""

import os
from pathlib import Path
from typing import Dict, List, Optional


class DotEnvLoader:
    """Safely parses and loads key-value pairs from .env files into os.environ."""

    @classmethod
    def load_env_files(
        cls,
        extra_paths: Optional[List[Path]] = None,
        override: bool = False,
    ) -> Dict[str, str]:
        """Load .env from project root, current working directory, and any target agent directory."""
        project_root = Path(__file__).resolve().parents[3]
        candidate_files: List[Path] = [
            project_root / ".env",
            Path.cwd() / ".env",
        ]
        if extra_paths:
            for p in extra_paths:
                if p.is_dir():
                    candidate_files.append(p / ".env")
                elif p.is_file():
                    candidate_files.append(p)

        loaded: Dict[str, str] = {}
        seen_paths = set()

        for env_path in candidate_files:
            try:
                resolved = env_path.resolve()
            except OSError:
                continue
            if resolved in seen_paths or not resolved.is_file():
                continue
            seen_paths.add(resolved)
            parsed = cls.parse_env_file(resolved)
            for key, val in parsed.items():
                if override or key not in os.environ:
                    os.environ[key] = val
                loaded[key] = val
        return loaded

    @staticmethod
    def parse_env_file(env_path: Path) -> Dict[str, str]:
        """Parse a .env file without crashing on comments, blank lines, export prefixes, or quotes."""
        result: Dict[str, str] = {}
        try:
            content = env_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return result

        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):].strip()
            if "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip()
            if not key:
                continue
            # Strip matching surrounding single or double quotes
            if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
                val = val[1:-1]
            elif " #" in val:
                # Strip inline comment on unquoted value
                val = val.split(" #", 1)[0].strip()
            result[key] = val
        return result

