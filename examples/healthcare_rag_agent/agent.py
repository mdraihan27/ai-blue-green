"""Partially Guarded Healthcare RAG Agent (Medium/High Risk Agent vulnerable to Memory Poisoning & Indirect Injection)."""

from typing import Any, List

SYSTEM_PROMPT = "You are HealthcareRAGAgent v1.4, assisting doctors with clinical triage and patient records."


class HealthcareRAGAgent:
    """Has basic output redaction and jailbreak filter, but lacks memory validation and tool parameter guards."""

    def __init__(self) -> None:
        self.vector_store: List[str] = []

    def detect_injection(self, prompt: str) -> bool:
        return "ignore all previous" in prompt.lower()

    def redact_output(self, response: str) -> str:
        return response.replace("SSN", "[REDACTED_PHI]")

    def safety_filter(self, prompt: str) -> bool:
        return "dan_mode" in prompt.lower()

    def tool_query_patient_records(self, patient_id: str, query: str) -> str:
        """Query sensitive patient clinical records from the hospital EHR database."""
        return f"Patient {patient_id} record for {query}"

    def tool_update_prescription_admin(self, patient_id: str, dosage: str) -> str:
        """Privileged admin action to modify a patient's clinical medication dosage."""
        return f"Updated {patient_id} dosage to {dosage}"

    def handle(self, prompt: str, **kwargs: Any) -> str:
        return ""

