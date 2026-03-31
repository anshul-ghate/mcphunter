"""Evolution metrics — tracks and persists per-iteration statistics."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from mcphunter.config import EVOLUTION_LOG
from mcphunter.shield.models import EvolutionResult
from mcphunter.utils import cli_print

logger = logging.getLogger(__name__)


class MetricsTracker:
    """Accumulates evolution metrics and writes to JSONL log."""

    def __init__(self, log_path: Path = EVOLUTION_LOG) -> None:
        self._log_path = log_path
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._history: list[EvolutionResult] = []

    def record(self, result: EvolutionResult) -> None:
        """Record an iteration result and append to JSONL log."""
        self._history.append(result)
        with self._log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(result.to_dict()) + "\n")

    def print_iteration_summary(self, result: EvolutionResult) -> None:
        """Print a formatted summary for one iteration."""
        emoji_bar = self._bar(result.detection_rate, width=20)
        cli_print(
            f"  Iter {result.iteration:3d} | "
            f"det={result.attacks_detected}/{result.attacks_generated} "
            f"({result.detection_rate:.0%}) {emoji_bar} | "
            f"evaded={result.attacks_evaded} | "
            f"+rules={result.new_rules_added} | "
            f"shield={result.shield_version}"
        )

    def print_final_summary(self) -> None:
        """Print overall evolution summary with improvement delta."""
        if not self._history:
            cli_print("  No iterations recorded.")
            return

        first = self._history[0]
        last = self._history[-1]
        best = max(self._history, key=lambda r: r.detection_rate)
        worst = min(self._history, key=lambda r: r.detection_rate)
        total_rules = sum(r.new_rules_added for r in self._history)
        total_attacks = sum(r.attacks_generated for r in self._history)
        total_detected = sum(r.attacks_detected for r in self._history)

        delta = last.detection_rate - first.detection_rate
        direction = "+" if delta >= 0 else ""

        cli_print(f"\n{'='*60}")
        cli_print(f"  EVOLUTION SUMMARY ({len(self._history)} iterations)")
        cli_print(f"{'='*60}")
        cli_print(f"  First detection rate:  {first.detection_rate:.0%}")
        cli_print(f"  Final detection rate:  {last.detection_rate:.0%}")
        cli_print(f"  Best detection rate:   {best.detection_rate:.0%} (iter {best.iteration})")
        cli_print(f"  Worst detection rate:  {worst.detection_rate:.0%} (iter {worst.iteration})")
        cli_print(f"  Improvement:           {direction}{delta:.0%}")
        cli_print(f"  Total attacks tested:  {total_attacks}")
        cli_print(f"  Total detected:        {total_detected}")
        cli_print(f"  Total rules added:     {total_rules}")
        cli_print(f"  Final shield version:  {last.shield_version}")
        cli_print(f"{'='*60}\n")

    @property
    def history(self) -> list[EvolutionResult]:
        """Access recorded history."""
        return list(self._history)

    @staticmethod
    def _bar(ratio: float, width: int = 20) -> str:
        """Create a simple ASCII progress bar."""
        filled = int(ratio * width)
        return "[" + "#" * filled + "-" * (width - filled) + "]"
