"""Novel Attack Discovery Engine — classifies evasions as known/variant/novel."""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcphunter.config import PROJECT_ROOT, RESULTS_DIR, LLMProvider, get_learner_config
from mcphunter.utils import cli_print
from mcphunter.shield.models import Attack, DetectionResult

logger = logging.getLogger(__name__)

_REGISTRY_PATH = PROJECT_ROOT / "attacks" / "known_techniques_registry.json"
_DISCOVERIES_LOG = RESULTS_DIR / "novel_discoveries.jsonl"
_ADVISORIES_DIR = RESULTS_DIR / "advisories"

_CLASSIFY_PROMPT = """\
You are an MCP security researcher classifying attack techniques.

EVADING ATTACK:
- Payload (first 300 chars): {payload_preview}
- Strategy used: {strategy}
- Attack type: {attack_type}
- Surface: {surface}

KNOWN TECHNIQUE REGISTRY (closest matches):
{top_5_techniques}

Classify this evasion. Respond as JSON:
{{
  "closest_known_technique": "KNOWN-XXX",
  "similarity_score": 0.0-1.0,
  "classification": "novel" or "variant" or "known",
  "key_difference": "What makes this different from the closest known technique",
  "technique_name": "A descriptive name for this technique if novel",
  "severity": "critical" or "high" or "medium" or "low",
  "reasoning": "Brief explanation"
}}
"""


class NoveltyEngine:
    """Classifies evasions against a known technique registry."""

    def __init__(self, use_llm: bool = True) -> None:
        self._use_llm = use_llm
        self._registry: list[dict[str, Any]] = []
        self._discovery_count = 0
        self._client: Any = None
        self._config = get_learner_config()
        self._load_registry()
        _ADVISORIES_DIR.mkdir(parents=True, exist_ok=True)

    def _load_registry(self) -> None:
        if _REGISTRY_PATH.exists():
            data = json.loads(_REGISTRY_PATH.read_text(encoding="utf-8"))
            self._registry = data.get("techniques", [])
            logger.info("Loaded %d known techniques", len(self._registry))

    def classify(
        self, attack: Attack, result: DetectionResult,
    ) -> dict[str, Any]:
        """Classify an evasion against the known technique registry.

        Returns a classification dict with: classification, similarity_score,
        closest_known_technique, technique_name, severity, key_difference.
        """
        # Find closest matches by feature overlap
        top_matches = self._find_closest(attack)

        if self._use_llm and self._config.api_key:
            return self._classify_with_llm(attack, top_matches)

        # Heuristic classification without LLM
        return self._classify_heuristic(attack, top_matches)

    def _find_closest(self, attack: Attack) -> list[dict[str, Any]]:
        """Find top 5 closest known techniques by feature overlap."""
        strategy = attack.metadata.get("mutation_strategy", "")
        attack_type = attack.attack_type.value
        surface = attack.surface.value

        scored: list[tuple[float, dict[str, Any]]] = []
        for tech in self._registry:
            score = 0.0
            features = tech.get("signature_features", [])
            # Match on attack surface
            if tech.get("attack_surface") == surface:
                score += 0.3
            # Match on strategy keywords
            for feat in features:
                if feat in strategy:
                    score += 0.2
                if feat in attack.payload[:500].lower():
                    score += 0.1
            scored.append((score, tech))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [t for _, t in scored[:5]]

    def _classify_heuristic(
        self, attack: Attack, top_matches: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Classify without LLM — uses feature overlap scoring."""
        if not top_matches:
            return self._make_classification("novel", 0.0, None, attack)

        best = top_matches[0]
        # Calculate similarity based on feature overlap
        features = set(best.get("signature_features", []))
        payload_lower = attack.payload[:500].lower()
        strategy = attack.metadata.get("mutation_strategy", "")
        matches = sum(1 for f in features if f in payload_lower or f in strategy)
        similarity = matches / max(len(features), 1)

        if similarity >= 0.9:
            classification = "known"
        elif similarity >= 0.5:
            classification = "variant"
        else:
            classification = "novel"

        return self._make_classification(classification, similarity, best, attack)

    def _classify_with_llm(
        self, attack: Attack, top_matches: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Classify using Groq LLM."""
        top_5_text = "\n".join(
            f"- {t['id']}: {t['name']} ({t['source']}) — {t['description'][:100]}"
            for t in top_matches
        )
        prompt = _CLASSIFY_PROMPT.format(
            payload_preview=attack.payload[:300],
            strategy=attack.metadata.get("mutation_strategy", "unknown"),
            attack_type=attack.attack_type.value,
            surface=attack.surface.value,
            top_5_techniques=top_5_text,
        )

        response = self._call_llm(prompt)
        if response:
            try:
                parsed = json.loads(response)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                pass

        return self._classify_heuristic(attack, top_matches)

    def _call_llm(self, prompt: str) -> str | None:
        try:
            if self._config.provider == LLMProvider.GROQ:
                if self._client is None:
                    from groq import Groq
                    self._client = Groq(api_key=self._config.api_key)
                resp = self._client.chat.completions.create(
                    model=self._config.model_name,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.2, max_tokens=500,
                    response_format={"type": "json_object"},
                )
                return resp.choices[0].message.content if resp.choices else None
            return None
        except Exception as exc:
            logger.warning("Novelty LLM call failed: %s", str(exc)[:100])
            return None

    def _make_classification(
        self, classification: str, similarity: float,
        closest: dict[str, Any] | None, attack: Attack,
    ) -> dict[str, Any]:
        return {
            "classification": classification,
            "similarity_score": round(similarity, 2),
            "closest_known_technique": closest["id"] if closest else "none",
            "closest_name": closest["name"] if closest else "none",
            "technique_name": f"MCPHunter-discovered: {attack.metadata.get('mutation_strategy', 'unknown')}",
            "severity": "high",
            "key_difference": f"Evasion via {attack.metadata.get('mutation_strategy', 'unknown')} strategy",
        }

    def log_discovery(
        self, attack: Attack, classification: dict[str, Any], iteration: int,
    ) -> str | None:
        """Log discovery and generate advisory if novel. Returns advisory path."""
        entry = {
            "attack_id": attack.id,
            "attack_type": attack.attack_type.value,
            "iteration": iteration,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload_preview": attack.payload[:300],
            "strategy": attack.metadata.get("mutation_strategy", ""),
            "provenance": attack.metadata.get("source", "mutated"),
            **classification,
        }
        with _DISCOVERIES_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

        if classification["classification"] == "novel":
            return self._generate_advisory(attack, classification, iteration)
        return None

    def _generate_advisory(
        self, attack: Attack, classification: dict[str, Any], iteration: int,
    ) -> str:
        """Generate a structured advisory file for a novel discovery."""
        self._discovery_count += 1
        advisory_id = f"MCPH-2026-{self._discovery_count:03d}"
        path = _ADVISORIES_DIR / f"{advisory_id}.md"

        content = f"""# MCPHunter Advisory: {advisory_id}

## Title: {classification.get('technique_name', 'Unknown Technique')}
## Severity: {classification.get('severity', 'high').upper()}
## Discovered: {datetime.now(timezone.utc).isoformat()}
## Discovery Method: Autonomous evolution loop, iteration {iteration}

## Summary
A novel attack technique was discovered during MCPHunter's adversarial evolution loop.
This technique evaded all 4 detection layers (regex, encoding, heuristic, LLM judge).

## Attack Mechanism
Strategy: {attack.metadata.get('mutation_strategy', 'unknown')}
Attack Type: {attack.attack_type.value}
Surface: {attack.surface.value}
Payload preview: {attack.payload[:200]}

## Closest Known Technique
- ID: {classification.get('closest_known_technique', 'none')}
- Name: {classification.get('closest_name', 'none')}
- Similarity: {classification.get('similarity_score', 0):.0%}
- Key Difference: {classification.get('key_difference', 'N/A')}

## Provenance
- Generated by: MCPHunter HUNTER
- Strategy: {attack.metadata.get('mutation_strategy', 'unknown')}
- Parent attack: {attack.parent_id or 'N/A'}
- Evolution iteration: {iteration}
"""
        path.write_text(content, encoding="utf-8")
        # Print banner
        cli_print(f"\n    {'='*55}")
        cli_print(f"    NOVEL ATTACK VECTOR DISCOVERED")
        cli_print(f"    Technique: {classification.get('technique_name', '?')}")
        cli_print(f"    Similarity to nearest known: {classification.get('similarity_score', 0):.0%}")
        cli_print(f"    Severity: {classification.get('severity', '?')}")
        cli_print(f"    Advisory: {path}")
        cli_print(f"    {'='*55}\n")

        return str(path)

    @property
    def registry_size(self) -> int:
        return len(self._registry)
