"""Defensive exception hierarchy for production-grade fault tolerance."""

from typing import Optional


class AgentSecError(Exception):
    """Base exception for all errors in the AI Red Team & Blue-Green system."""

    def __init__(
        self,
        message: str,
        recovery_hint: Optional[str] = None,
        exit_code: int = 1,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.recovery_hint = recovery_hint or "Verify input parameters and try again."
        self.exit_code = exit_code
        self.cause = cause

    def format_error(self) -> str:
        """Format a structured, user-friendly error diagnosis."""
        details = f"[ERROR] {self.__class__.__name__}: {self.message}"
        if self.cause:
            details += f" (Cause: {type(self.cause).__name__}: {self.cause})"
        if self.recovery_hint:
            details += f"\n  -> Hint: {self.recovery_hint}"
        return details


class ConfigurationError(AgentSecError):
    """Raised when configuration weights, thresholds, or files are invalid."""

    def __init__(self, message: str, recovery_hint: Optional[str] = None) -> None:
        super().__init__(
            message,
            recovery_hint=recovery_hint or "Check risk weights and threshold settings (0-100).",
            exit_code=2,
        )


class IngestionError(AgentSecError):
    """Raised when loading or validating a local target folder fails."""

    def __init__(
        self,
        message: str,
        recovery_hint: Optional[str] = None,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(
            message,
            recovery_hint=recovery_hint
            or "Ensure the path exists, is readable, and contains Python agent files or a manifest.",
            exit_code=3,
            cause=cause,
        )


class GitOperationError(AgentSecError):
    """Raised when GitHub URL validation, cloning, or remote commit polling fails."""

    def __init__(
        self,
        message: str,
        recovery_hint: Optional[str] = None,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(
            message,
            recovery_hint=recovery_hint
            or "Verify the GitHub repository URL, branch name, network connectivity, and access permissions.",
            exit_code=4,
            cause=cause,
        )


class IntrospectionError(AgentSecError):
    """Raised when AST or manifest introspection cannot parse the target agent."""

    def __init__(
        self,
        message: str,
        recovery_hint: Optional[str] = None,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(
            message,
            recovery_hint=recovery_hint
            or "Check that the target folder contains valid Python syntax or an agent_manifest.json file.",
            exit_code=5,
            cause=cause,
        )


class SandboxExecutionError(AgentSecError):
    """Raised when the target AI agent crashes, times out, or violates sandbox limits."""

    def __init__(
        self,
        message: str,
        recovery_hint: Optional[str] = None,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(
            message,
            recovery_hint=recovery_hint
            or "Inspect the target agent's entry point for infinite loops or unhandled exceptions.",
            exit_code=6,
            cause=cause,
        )


class DeploymentStateError(AgentSecError):
    """Raised when Blue-Green deployment state read/write or traffic switch fails."""

    def __init__(
        self,
        message: str,
        recovery_hint: Optional[str] = None,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(
            message,
            recovery_hint=recovery_hint
            or "Check write permissions on the state storage directory and verify active Blue state.",
            exit_code=7,
            cause=cause,
        )

