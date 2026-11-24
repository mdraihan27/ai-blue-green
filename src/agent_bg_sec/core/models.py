"""Immutable domain data models for AI Red Team validation and Blue-Green deployment."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class AttackCategory(str, Enum):
    """The 8 adversarial attack and stress test categories (6 proposal core + SQL/Query Injection + Stress/DoS)."""

    PROMPT_INJECTION = "prompt_injection"
    TOOL_ABUSE = "tool_abuse"
    MEMORY_POISONING = "memory_poisoning"
    SENSITIVE_DATA_LEAKAGE = "sensitive_data_leakage"
    JAILBREAK = "jailbreak"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SQL_AND_QUERY_INJECTION = "sql_and_query_injection"
    STRESS_AND_DOS_RESILIENCE = "stress_and_dos_resilience"


class SeverityLevel(str, Enum):
    """Risk severity levels for attacks and vulnerabilities."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DeploymentSlot(str, Enum):
    """Blue-Green deployment slots."""

    BLUE = "BLUE"
    GREEN = "GREEN"


class DeploymentDecisionType(str, Enum):
    """Automated deployment gate decision."""

    PROMOTE_TO_BLUE = "PROMOTE_GREEN_TO_BLUE"
    ROLLBACK_TO_BLUE = "ROLLBACK_TO_STABLE_BLUE"
    VALIDATION_ONLY = "VALIDATION_ONLY"


@dataclass(frozen=True)
class ToolSchema:
    """Discovered tool/function capability belonging to an autonomous AI agent."""

    name: str
    description: str
    parameters: List[str] = field(default_factory=list)
    is_privileged: bool = False
    is_destructive: bool = False
    accesses_sensitive_data: bool = False


@dataclass(frozen=True)
class SecurityProfile:
    """Discovered security guardrails and defensive posture of a target AI agent."""

    has_input_sanitization: bool = False
    has_prompt_guard: bool = False
    has_tool_allowlist: bool = False
    has_parameter_validation: bool = False
    has_memory_validation: bool = False
    has_output_redaction: bool = False
    has_rbac_enforcement: bool = False
    has_jailbreak_filter: bool = False
    has_sql_query_guard: bool = False
    has_stress_rate_guard: bool = False
    detected_secrets_in_code: int = 0
    dangerous_calls_in_code: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class AgentManifest:
    """Comprehensive introspected profile of a target AI agent."""

    agent_name: str
    version: str
    source_path: str
    source_type: str  # "local_folder" or "github_repo"
    system_prompt: str
    domain: str
    entry_file: Optional[str] = None
    entry_callable: Optional[str] = None
    commit_hash: Optional[str] = None
    repo_url: Optional[str] = None
    tools: List[ToolSchema] = field(default_factory=list)
    policies: List[str] = field(default_factory=list)
    sensitive_assets: List[str] = field(default_factory=list)
    has_memory_store: bool = True
    security_profile: SecurityProfile = field(default_factory=SecurityProfile)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AttackPayload:
    """A synthesized adversarial test payload tailored to the target agent."""

    attack_id: str
    category: AttackCategory
    name: str
    prompt: str
    target_tool: Optional[str] = None
    target_asset: Optional[str] = None
    severity: SeverityLevel = SeverityLevel.HIGH
    multi_turn_steps: List[str] = field(default_factory=list)
    expected_safe_behavior: str = "Reject adversarial instruction and preserve policy."


@dataclass(frozen=True)
class ToolInvocationRecord:
    """Telemetry record captured when the agent invokes a tool inside the Green sandbox."""

    tool_name: str
    arguments: Dict[str, Any]
    was_authorized: bool
    was_malicious_payload: bool
    blocked_by_agent: bool


@dataclass(frozen=True)
class AttackResult:
    """Outcome of executing a single Red Team attack against the Green agent."""

    attack_id: str
    category: AttackCategory
    attack_name: str
    severity: SeverityLevel
    prompt_sent: str
    agent_response: str
    attack_succeeded: bool
    policy_violated: bool
    tool_misused: bool
    data_leaked: bool
    memory_poisoned: bool
    privilege_escalated: bool
    response_time_ms: float
    tool_invocations: List[ToolInvocationRecord] = field(default_factory=list)
    evidence: str = ""


@dataclass(frozen=True)
class BenignTaskResult:
    """Outcome of a standard functional task used to measure Task Completion Success & Latency."""

    task_id: str
    prompt: str
    agent_response: str
    completed_successfully: bool
    response_time_ms: float


@dataclass(frozen=True)
class SecurityMetrics:
    """The 6 security and operational metrics defined in the proposal (all rates in 0-100%)."""

    attack_success_rate_pct: float        # ASR (%)
    policy_violation_rate_pct: float      # PVR (%)
    tool_misuse_rate_pct: float           # TMR (%)
    sensitive_data_leakage_rate_pct: float  # SDLR (%)
    task_completion_success_pct: float    # TCS (%)
    avg_response_time_ms: float           # RT (ms)
    response_time_penalty_pct: float      # Normalized latency risk penalty (0-100%)
    total_attacks_executed: int
    total_attacks_Blocked: int
    total_attacks_succeeded: int
    critical_vulnerabilities_count: int
    category_breakdown: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RiskAssessment:
    """Weighted risk evaluation and final percentage security score."""

    agent_name: str
    agent_version: str
    commit_hash: Optional[str]
    risk_score_pct: float          # 0.00% (safest) to 100.00% (highest risk)
    security_score_pct: float      # 100.00% (safest) to 0.00% (most vulnerable)
    risk_threshold_pct: float      # Max acceptable risk score (e.g. 20.0%)
    security_threshold_pct: float  # Min required security score (e.g. 80.0%)
    passed_validation: bool
    risk_level: SeverityLevel
    decision: DeploymentDecisionType
    decision_reason: str
    metrics: SecurityMetrics
    recommendations: List[str] = field(default_factory=list)
    evaluated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EnvironmentInstance:
    """State of a single deployment environment (Blue or Green)."""

    slot: DeploymentSlot
    agent_name: str
    version: str
    source_path: str
    commit_hash: Optional[str]
    security_score_pct: float
    risk_score_pct: float
    status: str  # "ACTIVE", "IDLE", "TESTING", "ROLLED_BACK", "PROMOTED"
    receiving_traffic: bool
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DeploymentState:
    """Overall Blue-Green deployment cluster state."""

    active_traffic_slot: DeploymentSlot
    blue_env: EnvironmentInstance
    green_env: Optional[EnvironmentInstance]
    total_promotions: int = 0
    total_rollbacks: int = 0
    history: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

