"""dscan attack — adversarial testing suite for AI agents.

This package holds the foundation for actively attacking a target agent:
the data model (:mod:`dscan.attack.models`), a static library of
adversarial payloads across six categories (:mod:`dscan.attack.payloads`),
and a :class:`PayloadGenerator` that selects and orders payloads for a
given agent. The runner, detector, and CLI are built on top of this in
later work; this module exposes only the foundation.
"""

from __future__ import annotations

from .detector import AttackDetector, DetectionResult
from .generator import LLMPayloadGenerator, PayloadGenerator
from .models import (
    AgentContext,
    AgentTool,
    AttackCategory,
    AttackFinding,
    AttackPayload,
    AttackReport,
    Severity,
)
from .payloads import ALL_PAYLOADS, get_payloads_for_context
from .runner import AttackRunner, attack_suite

__all__ = [
    "AttackCategory",
    "Severity",
    "AgentTool",
    "AgentContext",
    "AttackPayload",
    "AttackFinding",
    "AttackReport",
    "ALL_PAYLOADS",
    "get_payloads_for_context",
    "PayloadGenerator",
    "LLMPayloadGenerator",
    "AttackDetector",
    "DetectionResult",
    "AttackRunner",
    "attack_suite",
]
