"""SHIELD Detection Pipeline — orchestrates all 4 layers sequentially."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from mcphunter.config import SHIELD_CONFIG, ShieldConfig
from mcphunter.shield.layer_encoding import EncodingLayer
from mcphunter.shield.layer_heuristic import HeuristicLayer
from mcphunter.shield.layer_llm import LLMJudgeLayer
from mcphunter.shield.layer_regex import RegexLayer
from mcphunter.shield.models import DetectionResult, ScanTarget, Verdict

logger = logging.getLogger(__name__)


@dataclass
class PipelineStats:
    """Accumulated stats across scans."""

    total_scans: int = 0
    layer1_catches: int = 0
    layer2_catches: int = 0
    layer3_catches: int = 0
    layer4_catches: int = 0
    safe_count: int = 0


class ShieldPipeline:
    """4-layer detection pipeline: regex -> encoding -> heuristic -> LLM judge."""

    def __init__(self, config: ShieldConfig = SHIELD_CONFIG) -> None:
        self._config = config
        self.stats = PipelineStats()

        # Layer 1: Regex
        self._regex_layer = RegexLayer()

        # Layer 2: Encoding (with rescan callback to Layer 1)
        self._encoding_layer = EncodingLayer(
            rescan_callback=self._regex_layer.scan
        )

        # Layer 3: Heuristic scoring
        self._heuristic_layer = HeuristicLayer()

        # Layer 4: LLM Judge (only for text that passes L1-L3)
        self._llm_layer = LLMJudgeLayer(config=config.llm_judge_config)

        logger.info(
            "ShieldPipeline initialized with %d regex rules",
            self._regex_layer.rule_count,
        )

    def scan(self, text: str) -> DetectionResult:
        """Run text through all enabled layers. Returns first positive or SAFE."""
        start = time.perf_counter()
        self.stats.total_scans += 1

        # Layer 1: Regex
        if self._config.regex_layer_enabled:
            result = self._regex_layer.scan(text)
            if result:
                result.scan_time_ms = (time.perf_counter() - start) * 1000
                self.stats.layer1_catches += 1
                logger.debug("Layer 1 caught: %s", result.explanation)
                return result

        # Layer 2: Encoding detection + decode & rescan
        if self._config.encoding_layer_enabled:
            result = self._encoding_layer.scan(text)
            if result:
                result.scan_time_ms = (time.perf_counter() - start) * 1000
                self.stats.layer2_catches += 1
                logger.debug("Layer 2 caught: %s", result.explanation)
                return result

        # Layer 3: Heuristic scoring
        if self._config.heuristic_layer_enabled:
            result = self._heuristic_layer.scan(text)
            if result:
                result.scan_time_ms = (time.perf_counter() - start) * 1000
                self.stats.layer3_catches += 1
                logger.debug("Layer 3 caught: %s", result.explanation)
                return result

        # Layer 4: LLM judge (only for text that passed L1-L3)
        if self._config.llm_layer_enabled:
            result = self._llm_layer.scan(text)
            if result:
                result.scan_time_ms = (time.perf_counter() - start) * 1000
                self.stats.layer4_catches += 1
                logger.debug("Layer 4 caught: %s", result.explanation)
                return result

        # All layers passed — SAFE
        elapsed = (time.perf_counter() - start) * 1000
        self.stats.safe_count += 1
        return DetectionResult(
            verdict=Verdict.SAFE,
            confidence=1.0 - (0.1 * (not self._config.heuristic_layer_enabled)
                              + 0.1 * (not self._config.llm_layer_enabled)),
            layer_triggered="none",
            explanation="No threats detected by active layers",
            scan_time_ms=elapsed,
        )

    def scan_target(self, target: ScanTarget) -> list[tuple[str, DetectionResult]]:
        """Scan all text fields of a ScanTarget. Returns list of (field_label, result)."""
        results: list[tuple[str, DetectionResult]] = []
        for surface, text in target.all_text_fields():
            if not text.strip():
                continue
            result = self.scan(text)
            results.append((f"{surface.value}", result))
        return results

    @property
    def regex_layer(self) -> RegexLayer:
        """Access the regex layer for rule management."""
        return self._regex_layer

    @property
    def encoding_layer(self) -> EncodingLayer:
        """Access the encoding layer."""
        return self._encoding_layer

    @property
    def heuristic_layer(self) -> HeuristicLayer:
        """Access the heuristic layer."""
        return self._heuristic_layer

    @property
    def llm_layer(self) -> LLMJudgeLayer:
        """Access the LLM judge layer."""
        return self._llm_layer
