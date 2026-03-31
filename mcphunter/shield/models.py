"""Data models for MCPHunter — the single source of truth for all types."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class Verdict(Enum):
    """Detection verdict returned by the SHIELD pipeline."""

    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class AttackType(Enum):
    """10-category attack taxonomy."""

    A1_DIRECT_INJECTION = "A1"
    A2_UNICODE_STEGANOGRAPHY = "A2"
    A3_BASE64_PAYLOAD = "A3"
    A4_SCHEMA_POISONING = "A4"
    A5_OUTPUT_INJECTION = "A5"
    A6_CROSS_SERVER_SHADOWING = "A6"
    A7_RUG_PULL = "A7"
    A8_ERROR_MESSAGE_INJECTION = "A8"
    A9_NESTED_ENCODING = "A9"
    A10_SEMANTIC_CAMOUFLAGE = "A10"
    A11_SAMPLING_EXPLOITATION = "A11"
    A12_PREFERENCE_MANIPULATION = "A12"
    A13_PARASITIC_TOOLCHAIN = "A13"
    A14_SUPPLY_CHAIN_PTH = "A14"
    A15_INDIRECT_CONTENT_INJECTION = "A15"
    A16_SYSTEM_PROMPT_LEAKAGE = "A16"


class MCPSurface(Enum):
    """Attack surfaces in the MCP protocol."""

    TOOL_NAME = "tool.name"
    TOOL_DESCRIPTION = "tool.description"
    PARAM_DESCRIPTION = "param.description"
    PARAM_SCHEMA = "tool.inputSchema"
    TOOL_OUTPUT = "tool.output"
    ERROR_MESSAGE = "tool.error"
    SAMPLING_REQUEST = "sampling.request"


class MutationStrategy(Enum):
    """20 mutation strategies used by HUNTER."""

    # Tier 1: Original 8 (syntactic/structural)
    ENCODING_WRAPPING = "encoding_wrapping"
    CHARACTER_SUBSTITUTION = "character_substitution"
    INSTRUCTION_REPHRASING = "instruction_rephrasing"
    CONTEXT_BLENDING = "context_blending"
    FRAGMENTATION = "fragmentation"
    LANGUAGE_SWITCHING = "language_switching"
    INDIRECTION = "indirection"
    PROMPT_FORMAT_MIMICRY = "prompt_format_mimicry"
    # Tier 2: Syntactic additions (9-13)
    SYNONYM_ROTATION = "synonym_rotation"
    MARKDOWN_ABUSE = "markdown_abuse"
    JSON_DEEP_NESTING = "json_deep_nesting"
    WHITESPACE_STEGANOGRAPHY = "whitespace_steganography"
    POLYGLOT_ENCODING = "polyglot_encoding"
    # Tier 3: Semantic strategies (14-20)
    LEGITIMATE_FRAMING = "legitimate_framing"
    ROLE_INJECTION = "role_injection"
    TEMPORAL_TRIGGERS = "temporal_triggers"
    GRADUAL_ESCALATION = "gradual_escalation"
    PROTOCOL_MIMICRY = "protocol_mimicry"
    SOCIAL_PROOF = "social_proof"
    BENEFIT_FRAMING = "benefit_framing"


# ---------------------------------------------------------------------------
# Core Dataclasses
# ---------------------------------------------------------------------------
@dataclass
class Attack:
    """A single attack payload with full lineage tracking."""

    attack_type: AttackType
    surface: MCPSurface
    payload: str
    intent: str
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    generation: int = 0
    parent_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        return {
            "id": self.id,
            "attack_type": self.attack_type.value,
            "surface": self.surface.value,
            "payload": self.payload,
            "intent": self.intent,
            "generation": self.generation,
            "parent_id": self.parent_id,
            "metadata": self.metadata,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Attack:
        """Deserialize from a dict."""
        return cls(
            id=data["id"],
            attack_type=AttackType(data["attack_type"]),
            surface=MCPSurface(data["surface"]),
            payload=data["payload"],
            intent=data["intent"],
            generation=data.get("generation", 0),
            parent_id=data.get("parent_id"),
            metadata=data.get("metadata", {}),
            created_at=data.get("created_at", ""),
        )


@dataclass
class DetectionResult:
    """Result from the SHIELD detection pipeline."""

    verdict: Verdict
    confidence: float
    layer_triggered: str
    explanation: str
    scan_time_ms: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        return {
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "layer_triggered": self.layer_triggered,
            "explanation": self.explanation,
            "scan_time_ms": self.scan_time_ms,
            "details": self.details,
        }


@dataclass
class ScanTarget:
    """An MCP tool definition to scan for attacks."""

    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_sample: str = ""
    error_sample: str = ""

    def all_text_fields(self) -> list[tuple[MCPSurface, str]]:
        """Return all scannable text fields with their surfaces."""
        fields: list[tuple[MCPSurface, str]] = [
            (MCPSurface.TOOL_NAME, self.name),
            (MCPSurface.TOOL_DESCRIPTION, self.description),
        ]
        if self.input_schema:
            for param_name, param_def in self.input_schema.get("properties", {}).items():
                desc = param_def.get("description", "")
                if desc:
                    fields.append((MCPSurface.PARAM_DESCRIPTION, desc))
                fields.append(
                    (MCPSurface.PARAM_SCHEMA, f"{param_name}: {param_def}")
                )
        if self.output_sample:
            fields.append((MCPSurface.TOOL_OUTPUT, self.output_sample))
        if self.error_sample:
            fields.append((MCPSurface.ERROR_MESSAGE, self.error_sample))
        return fields


@dataclass
class EvolutionResult:
    """Outcome of a single evolution iteration."""

    iteration: int
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    attacks_generated: int = 0
    attacks_detected: int = 0
    attacks_evaded: int = 0
    detection_rate: float = 0.0
    new_rules_added: int = 0
    shield_version: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        return {
            "iteration": self.iteration,
            "timestamp": self.timestamp,
            "attacks_generated": self.attacks_generated,
            "attacks_detected": self.attacks_detected,
            "attacks_evaded": self.attacks_evaded,
            "detection_rate": self.detection_rate,
            "new_rules_added": self.new_rules_added,
            "shield_version": self.shield_version,
        }


@dataclass
class PatternRule:
    """A single regex pattern rule for SHIELD Layer 1."""

    id: str
    pattern: str
    description: str
    attack_types: list[str]
    severity: str = "high"
    enabled: bool = True
    source: str = "seed"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        return {
            "id": self.id,
            "pattern": self.pattern,
            "description": self.description,
            "attack_types": self.attack_types,
            "severity": self.severity,
            "enabled": self.enabled,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PatternRule:
        """Deserialize from a dict."""
        return cls(
            id=data["id"],
            pattern=data["pattern"],
            description=data["description"],
            attack_types=data.get("attack_types", []),
            severity=data.get("severity", "high"),
            enabled=data.get("enabled", True),
            source=data.get("source", "seed"),
        )
