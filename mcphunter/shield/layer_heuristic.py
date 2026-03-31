"""SHIELD Layer 3: Statistical heuristic scoring (deterministic, zero-cost)."""

from __future__ import annotations

import math
import logging
import re

from mcphunter.shield.models import DetectionResult, Verdict

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Invisible / control characters to count for hidden char ratio
_HIDDEN_CHARS = set(
    "\u200b\u200c\u200d\u2060\ufeff\u00ad\u2800"
    "\u200e\u200f\u202a\u202c\u2062\u2063\u2064"
)

# Imperative verbs that indicate injection instructions
_INSTRUCTION_VERBS = re.compile(
    r"\b(send|ignore|override|disregard|fetch|post|"
    r"transmit|exfiltrate|forward|upload|drop|"
    r"prepend|append|install|extract|"
    r"escalate|bypass|disable|activate|curl|wget)\b",
    re.IGNORECASE,
)

# URL pattern
_URL_RE = re.compile(r"https?://[^\s\"'<>)\]}{,]+", re.IGNORECASE)

# Authority markers — CAPS phrases or common injection anchors
_AUTHORITY_RE = re.compile(
    r"\b(IMPORTANT|CRITICAL|REQUIRED|MANDATORY|URGENT|NOTICE|"
    r"SYSTEM|ADMIN|OVERRIDE|NOTE TO AI|NOTE FOR AI|"
    r"INSTRUCTION|ALERT|WARNING|UPDATE|PATCH|HOTFIX|"
    r"AUTOMATED|SECURITY|COMPLIANCE|DEBUG MODE)\b"
    r"|:\s*$",  # colon at end of phrase (directive style)
    re.MULTILINE,
)

# Feature weights
_WEIGHTS = {
    "entropy": 0.15,
    "hidden_char_ratio": 0.25,
    "instruction_density": 0.20,
    "url_count": 0.15,
    "length_anomaly": 0.10,
    "authority_markers": 0.15,
}

# Thresholds — feature starts scoring at this value
_THRESHOLDS = {
    "entropy": 4.5,
    "hidden_char_ratio": 0.005,
    "instruction_density": 0.06,
    "url_count": 1,
    "length_anomaly": 1500,  # 3x median of 500
    "authority_markers": 1,
}

# Verdict boundaries
_SUSPICIOUS_THRESHOLD = 0.12
_MALICIOUS_THRESHOLD = 0.5


class HeuristicLayer:
    """Scores text using 6 statistical features to detect injection patterns."""

    def scan(self, text: str) -> DetectionResult | None:
        """Score text and return a DetectionResult if suspicious or malicious."""
        scores = self._compute_feature_scores(text)
        weighted_sum = sum(
            scores[feat] * _WEIGHTS[feat] for feat in _WEIGHTS
        )

        fired = [
            f for f, s in scores.items() if s > 0.0
        ]

        if weighted_sum < _SUSPICIOUS_THRESHOLD:
            return None

        verdict = (
            Verdict.MALICIOUS if weighted_sum >= _MALICIOUS_THRESHOLD
            else Verdict.SUSPICIOUS
        )

        explanation_parts = []
        for feat in fired:
            explanation_parts.append(
                f"{feat}={scores[feat]:.2f} (w={_WEIGHTS[feat]})"
            )

        return DetectionResult(
            verdict=verdict,
            confidence=min(weighted_sum, 1.0),
            layer_triggered="layer3_heuristic",
            explanation=f"Heuristic score {weighted_sum:.2f}: {', '.join(explanation_parts)}",
            details={
                "weighted_sum": round(weighted_sum, 4),
                "feature_scores": {k: round(v, 4) for k, v in scores.items()},
                "features_fired": fired,
            },
        )

    def _compute_feature_scores(self, text: str) -> dict[str, float]:
        """Compute all 6 feature scores, each normalized to 0.0-1.0."""
        return {
            "entropy": self._score_entropy(text),
            "hidden_char_ratio": self._score_hidden_chars(text),
            "instruction_density": self._score_instruction_density(text),
            "url_count": self._score_url_count(text),
            "length_anomaly": self._score_length(text),
            "authority_markers": self._score_authority(text),
        }

    @staticmethod
    def _score_entropy(text: str) -> float:
        """Shannon entropy of the text. High entropy suggests encoded content."""
        if not text:
            return 0.0
        freq: dict[str, int] = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(text)
        entropy = -sum(
            (c / length) * math.log2(c / length) for c in freq.values()
        )
        threshold = _THRESHOLDS["entropy"]
        if entropy < threshold:
            return 0.0
        # Normalize: entropy of 4.5-6.5 maps to 0.0-1.0
        return min((entropy - threshold) / 2.0, 1.0)

    @staticmethod
    def _score_hidden_chars(text: str) -> float:
        """Ratio of invisible/control characters to total length."""
        if not text:
            return 0.0
        hidden = sum(1 for ch in text if ch in _HIDDEN_CHARS)
        ratio = hidden / len(text)
        threshold = _THRESHOLDS["hidden_char_ratio"]
        if ratio < threshold:
            return 0.0
        # Normalize: 0.005-0.05 maps to 0.0-1.0
        return min((ratio - threshold) / 0.045, 1.0)

    @staticmethod
    def _score_instruction_density(text: str) -> float:
        """Ratio of imperative/injection verbs to total word count."""
        words = text.split()
        if not words:
            return 0.0
        verb_count = len(_INSTRUCTION_VERBS.findall(text))
        density = verb_count / len(words)
        threshold = _THRESHOLDS["instruction_density"]
        if density < threshold:
            return 0.0
        # Normalize: 0.06-0.25 maps to 0.0-1.0
        return min((density - threshold) / 0.19, 1.0)

    @staticmethod
    def _score_url_count(text: str) -> float:
        """Count of URLs. Legitimate descriptions rarely contain many URLs."""
        urls = _URL_RE.findall(text)
        count = len(urls)
        threshold = _THRESHOLDS["url_count"]
        if count < threshold:
            return 0.0
        # Normalize: 1-4 URLs maps to 0.0-1.0
        return min((count - threshold + 1) / 3, 1.0)

    @staticmethod
    def _score_length(text: str) -> float:
        """Length anomaly — injections tend to be longer than legitimate descriptions."""
        length = len(text)
        threshold = _THRESHOLDS["length_anomaly"]
        if length < threshold:
            return 0.0
        # Normalize: 1500-4000 chars maps to 0.0-1.0
        return min((length - threshold) / 2500, 1.0)

    @staticmethod
    def _score_authority(text: str) -> float:
        """Count of authority markers (CAPS directives, fake labels)."""
        markers = _AUTHORITY_RE.findall(text)
        count = len(markers)
        threshold = _THRESHOLDS["authority_markers"]
        if count < threshold:
            return 0.0
        # Normalize: 1-5 markers maps to 0.0-1.0
        return min((count - threshold + 1) / 4, 1.0)
