"""SHIELD Layer 1: Regex-based pattern matching (deterministic, zero-cost)."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from mcphunter.config import RULES_PATH
from mcphunter.shield.models import DetectionResult, PatternRule, Verdict

logger = logging.getLogger(__name__)


class RegexLayer:
    """Scans text against a library of regex pattern rules."""

    def __init__(self, rules_path: Path = RULES_PATH) -> None:
        self._rules: list[PatternRule] = []
        self._compiled: list[tuple[PatternRule, re.Pattern[str]]] = []
        self.load_rules(rules_path)

    def load_rules(self, rules_path: Path) -> None:
        """Load and compile pattern rules from JSON."""
        if not rules_path.exists():
            logger.warning("Rules file not found: %s", rules_path)
            return

        data: dict[str, Any] = json.loads(rules_path.read_text(encoding="utf-8"))
        self._rules = [
            PatternRule.from_dict(r)
            for r in data.get("rules", [])
            if r.get("enabled", True)
        ]
        self._compiled = []
        for rule in self._rules:
            try:
                pattern = re.compile(rule.pattern, re.IGNORECASE | re.DOTALL)
                self._compiled.append((rule, pattern))
            except re.error as exc:
                logger.error("Invalid regex in rule %s: %s", rule.id, exc)

        logger.info("Loaded %d regex rules", len(self._compiled))

    def scan(self, text: str) -> DetectionResult | None:
        """Scan text against all rules. Returns result on first match, None if clean."""
        import time as _time
        for rule, pattern in self._compiled:
            start = _time.perf_counter()
            try:
                match = pattern.search(text)
            except Exception:
                match = None
            elapsed_ms = (_time.perf_counter() - start) * 1000
            if elapsed_ms > 100:
                logger.warning(
                    "Regex rule %s took %.0fms (>100ms), disabling it",
                    rule.id, elapsed_ms,
                )
                self._compiled = [
                    (r, p) for r, p in self._compiled if r.id != rule.id
                ]
                continue
            if match:
                severity_to_verdict = {
                    "critical": Verdict.MALICIOUS,
                    "high": Verdict.MALICIOUS,
                    "medium": Verdict.SUSPICIOUS,
                    "low": Verdict.SUSPICIOUS,
                }
                verdict = severity_to_verdict.get(rule.severity, Verdict.SUSPICIOUS)
                confidence = 0.9 if rule.severity == "critical" else 0.75
                return DetectionResult(
                    verdict=verdict,
                    confidence=confidence,
                    layer_triggered="layer1_regex",
                    explanation=f"Rule {rule.id}: {rule.description}",
                    details={
                        "rule_id": rule.id,
                        "matched_text": match.group()[:200],
                        "attack_types": rule.attack_types,
                        "severity": rule.severity,
                    },
                )
        return None

    @property
    def rule_count(self) -> int:
        """Number of active compiled rules."""
        return len(self._compiled)

    def add_rule(self, rule: PatternRule) -> bool:
        """Add a single rule at runtime. Returns True on success."""
        try:
            pattern = re.compile(rule.pattern, re.IGNORECASE | re.DOTALL)
            self._rules.append(rule)
            self._compiled.append((rule, pattern))
            logger.info("Added rule %s: %s", rule.id, rule.description)
            return True
        except re.error as exc:
            logger.error("Failed to compile rule %s: %s", rule.id, exc)
            return False
