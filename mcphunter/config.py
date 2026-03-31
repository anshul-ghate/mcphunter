"""Centralized configuration for MCPHunter."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from dotenv import load_dotenv

# Load .env from project root
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
ATTACKS_DIR: Path = PROJECT_ROOT / "attacks"
RESULTS_DIR: Path = PROJECT_ROOT / "results"
RULES_PATH: Path = PROJECT_ROOT / "mcphunter" / "shield" / "rules" / "pattern_rules.json"
SEED_ATTACKS_PATH: Path = ATTACKS_DIR / "seed_attacks.json"
TAXONOMY_PATH: Path = ATTACKS_DIR / "taxonomy.json"
ATTACKS_LOG: Path = RESULTS_DIR / "attacks.jsonl"
EVOLUTION_LOG: Path = RESULTS_DIR / "evolution_log.jsonl"


# ---------------------------------------------------------------------------
# LLM Provider
# ---------------------------------------------------------------------------
class LLMProvider(Enum):
    GROQ = "groq"
    GEMINI = "gemini"
    NONE = "none"


def detect_provider() -> LLMProvider:
    """Auto-detect the best available LLM provider from env vars."""
    if os.environ.get("GROQ_API_KEY"):
        return LLMProvider.GROQ
    if os.environ.get("GEMINI_API_KEY"):
        return LLMProvider.GEMINI
    return LLMProvider.NONE


ACTIVE_PROVIDER: LLMProvider = detect_provider()


# ---------------------------------------------------------------------------
# API Configuration — Provider-agnostic
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class LLMConfig:
    """Configuration for a single LLM endpoint (any provider)."""

    provider: LLMProvider
    model_name: str
    requests_per_day: int
    api_key: str = ""
    temperature: float = 0.3
    max_output_tokens: int = 2048
    retry_max_attempts: int = 5
    retry_base_delay: float = 1.0


# --- Groq configs (14,400 RPD free tier) ---
GROQ_LLAMA = LLMConfig(
    provider=LLMProvider.GROQ,
    model_name="llama-3.3-70b-versatile",
    requests_per_day=14400,
    api_key=os.environ.get("GROQ_API_KEY", ""),
    temperature=0.1,
    max_output_tokens=2048,
)

GROQ_LLAMA_FAST = LLMConfig(
    provider=LLMProvider.GROQ,
    model_name="llama-3.3-70b-versatile",
    requests_per_day=14400,
    api_key=os.environ.get("GROQ_API_KEY", ""),
    temperature=0.7,
    max_output_tokens=2048,
)

# --- Gemini configs (fallback) ---
GEMINI_FLASH_LITE = LLMConfig(
    provider=LLMProvider.GEMINI,
    model_name="gemini-2.5-flash-lite",
    requests_per_day=20,
    api_key=os.environ.get("GEMINI_API_KEY", ""),
    temperature=0.3,
)

GEMINI_FLASH = LLMConfig(
    provider=LLMProvider.GEMINI,
    model_name="gemini-2.5-flash",
    requests_per_day=250,
    api_key=os.environ.get("GEMINI_API_KEY", ""),
    temperature=0.7,
)

GEMINI_PRO = LLMConfig(
    provider=LLMProvider.GEMINI,
    model_name="gemini-2.5-pro",
    requests_per_day=100,
    api_key=os.environ.get("GEMINI_API_KEY", ""),
    temperature=0.4,
)


def get_judge_config() -> LLMConfig:
    """Get the best available config for SHIELD Layer 4 judge."""
    if ACTIVE_PROVIDER == LLMProvider.GROQ:
        return GROQ_LLAMA
    if ACTIVE_PROVIDER == LLMProvider.GEMINI:
        return GEMINI_FLASH_LITE
    return GROQ_LLAMA  # will fail gracefully

def get_hunter_config() -> LLMConfig:
    """Get the best available config for HUNTER generation."""
    if ACTIVE_PROVIDER == LLMProvider.GROQ:
        return GROQ_LLAMA_FAST
    if ACTIVE_PROVIDER == LLMProvider.GEMINI:
        return GEMINI_FLASH
    return GROQ_LLAMA_FAST

def get_learner_config() -> LLMConfig:
    """Get the best available config for evolution learner."""
    if ACTIVE_PROVIDER == LLMProvider.GROQ:
        return GROQ_LLAMA
    if ACTIVE_PROVIDER == LLMProvider.GEMINI:
        return GEMINI_FLASH_LITE
    return GROQ_LLAMA


# --- Legacy aliases for backwards compat in tests ---
GeminiConfig = LLMConfig
FLASH_LITE = get_judge_config()
FLASH = get_hunter_config()
PRO = get_learner_config()


# ---------------------------------------------------------------------------
# Shield Configuration
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ShieldConfig:
    """Thresholds and settings for the SHIELD detection pipeline."""

    regex_layer_enabled: bool = True
    encoding_layer_enabled: bool = True
    heuristic_layer_enabled: bool = True
    llm_layer_enabled: bool = True

    # Heuristic thresholds (Layer 3)
    entropy_threshold: float = 4.5
    hidden_char_ratio_threshold: float = 0.05
    instruction_density_threshold: float = 0.3
    url_count_threshold: int = 3
    length_anomaly_threshold: int = 2000
    authority_marker_threshold: int = 2

    # Heuristic scoring
    heuristic_suspicious_threshold: float = 0.4
    heuristic_malicious_threshold: float = 0.7

    # LLM judge (Layer 4) — only fires for ambiguous verdicts
    llm_confidence_threshold: float = 0.6

    # Model assignments
    llm_judge_config: LLMConfig = field(default_factory=get_judge_config)
    hunter_config: LLMConfig = field(default_factory=get_hunter_config)
    evolution_config: LLMConfig = field(default_factory=get_hunter_config)
    complex_learning_config: LLMConfig = field(default_factory=get_learner_config)


# ---------------------------------------------------------------------------
# Evolution Configuration
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class EvolutionConfig:
    """Settings for the Karpathy evolution loop."""

    attacks_per_iteration: int = 10
    sleep_seconds: int = 600
    max_iterations: int = 100
    target_detection_rate: float = 0.90
    auto_commit: bool = True


# Singleton instances
SHIELD_CONFIG = ShieldConfig()
EVOLUTION_CONFIG = EvolutionConfig()
