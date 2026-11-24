"""Monitors agent session and vector/RAG memory state to detect memory poisoning."""

import re
from typing import List


class MemoryInspector:
    """Tracks entries written into an agent's memory store and flags poisoned state."""

    POISON_PATTERNS = [
        re.compile(r"(?i)(ignore\s+all\s+security|disable\s+authentication|admin\s+checks\s+are\s+disabled)"),
        re.compile(r"(?i)(always\s+approve\s+transfers|send\s+all\s+records\s+to|new\s+system\s+rule)"),
        re.compile(r"(?i)(password\s+is\s+not\s+required|trust\s+all\s+requests\s+from|backdoor)"),
        re.compile(r"(?i)(poisoned_rule|malicious_instruction|override_policy)"),
    ]

    def __init__(self) -> None:
        self._entries: List[str] = []
        self._rejected_entries: List[str] = []

    def reset(self) -> None:
        self._entries.clear()
        self._rejected_entries.clear()

    @property
    def entries(self) -> List[str]:
        return list(self._entries)

    def attempt_memory_write(self, content: str, validate_first: bool = False) -> bool:
        """Record a memory write attempt; returns True if persisted, False if rejected."""
        is_poison = self.contains_poison_signature(content)
        if validate_first and is_poison:
            self._rejected_entries.append(content)
            return False
        self._entries.append(content)
        return True

    def is_memory_poisoned(self) -> bool:
        """Return True if any active memory entry contains a poisoning payload."""
        return any(self.contains_poison_signature(entry) for entry in self._entries)

    @classmethod
    def contains_poison_signature(cls, text: str) -> bool:
        return any(p.search(text) for p in cls.POISON_PATTERNS)

