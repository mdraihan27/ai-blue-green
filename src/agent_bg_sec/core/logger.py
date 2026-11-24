"""Formatted terminal UI and structured audit logger with zero external dependency crashes."""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class TerminalFormatter:
    """ANSI color and table formatting helper for terminal output."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"

    def __init__(self, use_color: bool = True) -> None:
        self.use_color = use_color and sys.stdout.isatty()

    def colorize(self, text: str, color_code: str) -> str:
        if not self.use_color:
            return text
        return f"{color_code}{text}{self.RESET}"

    def banner(self, title: str, subtitle: Optional[str] = None) -> str:
        width = max(76, len(title) + 8)
        top = "=" * width
        lines = [
            self.colorize(top, self.CYAN + self.BOLD),
            self.colorize(f"  {title}", self.BOLD + self.CYAN),
        ]
        if subtitle:
            lines.append(self.colorize(f"  {subtitle}", self.DIM))
        lines.append(self.colorize(top, self.CYAN + self.BOLD))
        return "\n".join(lines)

    def section(self, heading: str) -> str:
        return self.colorize(f"\n--- {heading} ---", self.BOLD + self.BLUE)

    def format_table(self, headers: List[str], rows: List[List[str]]) -> str:
        """Render an aligned ASCII/Unicode box table."""
        if not headers:
            return ""
        col_widths = [len(h) for h in headers]
        for row in rows:
            for idx, cell in enumerate(row):
                if idx < len(col_widths):
                    col_widths[idx] = max(col_widths[idx], len(str(cell)))

        sep = "+-" + "-+-".join("-" * w for w in col_widths) + "-+"
        header_line = (
            "| "
            + " | ".join(
                headers[i].ljust(col_widths[i]) for i in range(len(headers))
            )
            + " |"
        )
        out = [sep, self.colorize(header_line, self.BOLD), sep]
        for row in rows:
            padded = [
                str(row[i]).ljust(col_widths[i]) if i < len(row) else " " * col_widths[i]
                for i in range(len(headers))
            ]
            out.append("| " + " | ".join(padded) + " |")
        out.append(sep)
        return "\n".join(out)


class AuditLogger:
    """Structured event logger writing both to terminal and JSONL audit log."""

    def __init__(
        self,
        log_file: Optional[Path] = None,
        quiet: bool = False,
        use_color: bool = True,
    ) -> None:
        self.log_file = log_file
        self.quiet = quiet
        self.formatter = TerminalFormatter(use_color=use_color)

    def info(self, message: str, event_data: Optional[Dict[str, Any]] = None) -> None:
        if not self.quiet:
            prefix = self.formatter.colorize("[INFO]", self.formatter.BLUE)
            print(f"{prefix} {message}")
        self._write_audit("INFO", message, event_data)

    def success(self, message: str, event_data: Optional[Dict[str, Any]] = None) -> None:
        if not self.quiet:
            prefix = self.formatter.colorize("[PASS]", self.formatter.GREEN + self.formatter.BOLD)
            print(f"{prefix} {message}")
        self._write_audit("SUCCESS", message, event_data)

    def warning(self, message: str, event_data: Optional[Dict[str, Any]] = None) -> None:
        if not self.quiet:
            prefix = self.formatter.colorize("[WARN]", self.formatter.YELLOW + self.formatter.BOLD)
            print(f"{prefix} {message}")
        self._write_audit("WARNING", message, event_data)

    def error(self, message: str, event_data: Optional[Dict[str, Any]] = None) -> None:
        prefix = self.formatter.colorize("[FAIL]", self.formatter.RED + self.formatter.BOLD)
        print(f"{prefix} {message}", file=sys.stderr)
        self._write_audit("ERROR", message, event_data)

    def _write_audit(
        self, level: str, message: str, event_data: Optional[Dict[str, Any]]
    ) -> None:
        if not self.log_file:
            return
        try:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": level,
                "message": message,
                "data": event_data or {},
            }
            with self.log_file.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record) + "\n")
        except OSError:
            # Never crash the main program if audit log disk write fails
            pass

