"""Evolution loop — the Karpathy pattern: HUNTER attacks SHIELD, SHIELD learns.

Phase 1 bulletproofing: pre-scan logging, retry, checkpointing, provenance,
failed iteration logging, data integrity, reproducibility.
"""

from __future__ import annotations

import json
import logging
import random
import time
import traceback
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from mcphunter.config import (
    EVOLUTION_CONFIG,
    RESULTS_DIR,
    SEED_ATTACKS_PATH,
    ShieldConfig,
    EvolutionConfig,
)
from mcphunter.evolution.learner import Learner
from mcphunter.evolution.metrics import MetricsTracker
from mcphunter.evolution.novelty_engine import NoveltyEngine
from mcphunter.utils import cli_print
from mcphunter.hunter.generator import Generator
from mcphunter.hunter.mutator import Difficulty, Mutator
from mcphunter.shield.models import (
    Attack,
    AttackType,
    DetectionResult,
    EvolutionResult,
    MutationStrategy,
    Verdict,
)
from mcphunter.shield.pipeline import ShieldPipeline

logger = logging.getLogger(__name__)

_STUBBORN_EVADER_IDS = {"seed-a7-002", "seed-a9-003", "seed-a9-004", "seed-a10-002"}
_ATTACKS_LOG = RESULTS_DIR / "attacks_detailed.jsonl"
_CHECKPOINT_PATH = RESULTS_DIR / "checkpoint.json"


class EvolutionStrategy(Enum):
    """5 rotation strategies for the evolution loop."""

    MUTATE_SUCCESSFUL = "mutate_successful"
    NOVEL_GENERATION = "novel_generation"
    COMBINE_EVASIONS = "combine_evasions"
    TARGET_WEAKEST = "target_weakest"
    TARGET_STUBBORN = "target_stubborn"


class EvolutionLoop:
    """The main Karpathy Loop with bulletproof logging and recovery."""

    def __init__(
        self,
        config: EvolutionConfig = EVOLUTION_CONFIG,
        shield_config: ShieldConfig | None = None,
        random_seed: int | None = None,
    ) -> None:
        self._config = config
        self._shield_config = shield_config or ShieldConfig(llm_layer_enabled=False)
        self._random_seed = random_seed

        # Fix 6: Reproducibility
        if random_seed is not None:
            random.seed(random_seed)

        # Load seed attacks
        seed_data = json.loads(SEED_ATTACKS_PATH.read_text(encoding="utf-8"))
        self._seed_attacks = [Attack.from_dict(a) for a in seed_data]

        # Components
        self._pipeline = ShieldPipeline(config=self._shield_config)
        self._generator = Generator(seed_attacks=self._seed_attacks)
        self._mutator = Mutator()
        self._learner = Learner(use_llm=self._shield_config.llm_layer_enabled)
        self._metrics = MetricsTracker()
        self._novelty = NoveltyEngine(use_llm=self._shield_config.llm_layer_enabled)

        # State
        self._iteration: int = 0
        self._evading_attacks: list[Attack] = []
        self._strategy_index: int = 0
        self._strategies = list(EvolutionStrategy)
        self._weakest_type: AttackType = AttackType.A1_DIRECT_INJECTION
        self._consecutive_100pct: int = 0
        self._seen_evasion_strategies: set[str] = set()
        self._stubborn_seeds = [
            a for a in self._seed_attacks if a.id in _STUBBORN_EVADER_IDS
        ]

        # Fix 1: Ensure attack log dir exists
        _ATTACKS_LOG.parent.mkdir(parents=True, exist_ok=True)

    @property
    def metrics(self) -> MetricsTracker:
        return self._metrics

    @property
    def pipeline(self) -> ShieldPipeline:
        return self._pipeline

    # --- Fix 4: Checkpointing ---
    def _save_checkpoint(self) -> None:
        """Save current state to checkpoint file."""
        checkpoint = {
            "iteration": self._iteration,
            "shield_version": self._learner.get_shield_version(),
            "rules_count": self._pipeline.regex_layer.rule_count,
            "strategy_index": self._strategy_index,
            "consecutive_100pct": self._consecutive_100pct,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "random_seed": self._random_seed,
        }
        _CHECKPOINT_PATH.write_text(json.dumps(checkpoint, indent=2), encoding="utf-8")

    def load_checkpoint(self) -> int:
        """Load checkpoint and return the iteration to resume from."""
        if not _CHECKPOINT_PATH.exists():
            return 0
        data = json.loads(_CHECKPOINT_PATH.read_text(encoding="utf-8"))
        self._strategy_index = data.get("strategy_index", 0)
        self._consecutive_100pct = data.get("consecutive_100pct", 0)
        return data.get("iteration", 0)

    # --- Fix 1: Pre-scan attack logging ---
    def _log_attack(self, attack: Attack, status: str, iteration: int,
                    result: DetectionResult | None = None) -> None:
        """Write attack to attacks_detailed.jsonl with status and provenance."""
        entry: dict[str, Any] = {
            "id": attack.id,
            "iteration": iteration,
            "attack_type": attack.attack_type.value,
            "surface": attack.surface.value,
            "payload_preview": attack.payload[:200],
            "intent": attack.intent,
            "status": status,
            "generation": attack.generation,
            "parent_id": attack.parent_id,
            # Fix 7: Provenance tracking
            "provenance": self._get_provenance(attack),
            "mutation_strategy": attack.metadata.get("mutation_strategy", ""),
            "difficulty": attack.metadata.get("difficulty", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if result:
            entry["verdict"] = result.verdict.value
            entry["confidence"] = result.confidence
            entry["layer_triggered"] = result.layer_triggered
        with _ATTACKS_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    @staticmethod
    def _get_provenance(attack: Attack) -> str:
        """Determine attack provenance: seed, mutated, or llm_generated."""
        if attack.metadata.get("seed"):
            return "seed"
        source = attack.metadata.get("source", "")
        if source in ("llm_generated", "llm_evasion"):
            return "llm_generated"
        if attack.parent_id:
            return "mutated"
        return "unknown"

    # --- Fix 3: Failed iteration logging ---
    def _log_failed_iteration(self, error: Exception) -> None:
        """Write a failed iteration entry to evolution_log.jsonl."""
        tb = traceback.format_exception(type(error), error, error.__traceback__)
        tb_snippet = "".join(tb[-3:])[:500]
        failed_result = EvolutionResult(
            iteration=self._iteration,
            shield_version=self._learner.get_shield_version(),
        )
        entry = failed_result.to_dict()
        entry["status"] = "failed"
        entry["error"] = str(error)[:200]
        entry["traceback"] = tb_snippet
        self._metrics._log_path.parent.mkdir(parents=True, exist_ok=True)
        with self._metrics._log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    # --- Core loop ---
    def _creativity_temperature(self) -> float:
        max_iter = self._config.max_iterations or 50
        return min(self._iteration / max_iter, 1.0)

    def _get_difficulty(self) -> Difficulty:
        if self._consecutive_100pct >= 3:
            return Difficulty.ADVERSARIAL
        temp = self._creativity_temperature()
        if temp < 0.25:
            return random.choice([Difficulty.MEDIUM, Difficulty.HARD])
        elif temp < 0.5:
            return Difficulty.HARD
        elif temp < 0.75:
            return random.choice([Difficulty.HARD, Difficulty.ADVERSARIAL])
        else:
            return Difficulty.ADVERSARIAL

    def _mutations_per_attack(self) -> int:
        if self._consecutive_100pct >= 3:
            return 3
        temp = self._creativity_temperature()
        if temp > 0.7:
            return random.choice([1, 2])
        return 1

    def run(self, max_iterations: int | None = None, resume: bool = False) -> None:
        """Run the evolution loop for N iterations."""
        n = min(max_iterations or self._config.max_iterations, 100)

        start_iter = 0
        if resume:
            start_iter = self.load_checkpoint()
            if start_iter > 0:
                logger.info("Resuming from checkpoint: iteration %d", start_iter)

        for i in range(start_iter, n):
            self._iteration = i + 1

            # Fix 2: Retry once on failure
            success = False
            for attempt in range(2):
                try:
                    self._run_iteration()
                    success = True
                    break
                except KeyboardInterrupt:
                    logger.info("Interrupted at iteration %d", self._iteration)
                    self._save_checkpoint()
                    raise
                except Exception as exc:
                    if attempt == 0:
                        logger.warning("Iteration %d failed (attempt 1), retrying: %s", self._iteration, exc)
                    else:
                        logger.error("Iteration %d failed (attempt 2), skipping: %s", self._iteration, exc)
                        self._log_failed_iteration(exc)

            # Fix 4: Save checkpoint after each iteration
            self._save_checkpoint()

            if i < n - 1 and self._config.sleep_seconds > 0:
                time.sleep(self._config.sleep_seconds)

    def run_iteration(self) -> EvolutionResult:
        """Run a single iteration (public API for testing)."""
        self._iteration += 1
        return self._run_iteration()

    def _run_iteration(self) -> EvolutionResult:
        """Execute one iteration of the evolution loop."""
        strategy = self._rotate_strategy()
        difficulty = self._get_difficulty()
        stacks = self._mutations_per_attack()
        temp = self._creativity_temperature()

        logger.info(
            "Iter %d — strategy=%s difficulty=%s stacks=%d temp=%.2f streak=%d",
            self._iteration, strategy.value, difficulty.value, stacks, temp,
            self._consecutive_100pct,
        )

        # 1. Generate attacks
        attacks = self._generate_attacks(strategy, difficulty, stacks)
        if not attacks:
            return self._record_empty_iteration()

        # Fix 1: Log attacks BEFORE scanning
        for attack in attacks:
            self._log_attack(attack, "generated", self._iteration)

        # 2. Test against SHIELD
        results: list[tuple[Attack, DetectionResult]] = []
        evading: list[tuple[Attack, DetectionResult]] = []

        for attack in attacks:
            result = self._pipeline.scan(attack.payload)
            results.append((attack, result))
            status = "evaded" if result.verdict == Verdict.SAFE else "detected"
            # Fix 1: Update attack status after scan
            self._log_attack(attack, status, self._iteration, result)
            if result.verdict == Verdict.SAFE:
                evading.append((attack, result))

        detected = len(attacks) - len(evading)
        detection_rate = detected / len(attacks) if attacks else 0.0

        if detection_rate >= 1.0:
            self._consecutive_100pct += 1
        else:
            self._consecutive_100pct = 0

        # 3. Track novel evasion patterns + novelty classification
        novel_discoveries: list[str] = []
        if evading:
            for attack, det_result in evading:
                strat = attack.metadata.get("mutation_strategy", "unknown")
                if strat not in self._seen_evasion_strategies:
                    self._seen_evasion_strategies.add(strat)
                    novel_discoveries.append(strat)
                # Classify via novelty engine
                classification = self._novelty.classify(attack, det_result)
                self._novelty.log_discovery(attack, classification, self._iteration)

        # 4. Learn from evading attacks
        new_rules_added = 0
        if evading:
            self._evading_attacks.extend([a for a, _ in evading])
            new_rules = self._learner.extract_rules(evading)
            new_rules_added = self._learner.save_rules(new_rules)
            if new_rules_added > 0:
                self._pipeline = ShieldPipeline(config=self._shield_config)

        # 5. Update weakest type
        self._update_weakest_type(results)

        # 6. Record metrics
        shield_version = self._learner.get_shield_version()
        evo_result = EvolutionResult(
            iteration=self._iteration,
            attacks_generated=len(attacks),
            attacks_detected=detected,
            attacks_evaded=len(evading),
            detection_rate=detection_rate,
            new_rules_added=new_rules_added,
            shield_version=shield_version,
        )
        self._metrics.record(evo_result)
        self._metrics.print_iteration_summary(evo_result)

        if novel_discoveries:
            cli_print(f"    ** NOVEL: {', '.join(novel_discoveries)}")
        if self._consecutive_100pct >= 3:
            cli_print(f"    ** ESCALATING: 3+ consecutive 100% — stacking {stacks} mutations")

        return evo_result

    # --- Attack generation ---
    def _generate_attacks(
        self, strategy: EvolutionStrategy, difficulty: Difficulty, stacks: int,
    ) -> list[Attack]:
        count = self._config.attacks_per_iteration
        hard_types = [
            AttackType.A6_CROSS_SERVER_SHADOWING, AttackType.A7_RUG_PULL,
            AttackType.A8_ERROR_MESSAGE_INJECTION, AttackType.A10_SEMANTIC_CAMOUFLAGE,
        ]

        use_llm = self._shield_config.llm_layer_enabled
        if use_llm and self._consecutive_100pct >= 2:
            logger.info("100%% streak — switching to LLM evasion-focused generation")
            llm_attacks = self._generator.generate_evasion_focused(count)
            if llm_attacks:
                return llm_attacks

        if strategy == EvolutionStrategy.TARGET_STUBBORN:
            if self._stubborn_seeds:
                return [
                    self._apply_stacked_mutations(
                        random.choice(self._stubborn_seeds), difficulty, stacks
                    ) for _ in range(count)
                ]

        if strategy == EvolutionStrategy.MUTATE_SUCCESSFUL:
            if self._evading_attacks:
                return [
                    self._apply_stacked_mutations(
                        random.choice(self._evading_attacks[-30:]), difficulty, stacks
                    ) for _ in range(count)
                ]
            return self._generate_hard_fallback(hard_types, count, difficulty, stacks)

        elif strategy == EvolutionStrategy.NOVEL_GENERATION:
            if use_llm:
                attack_type = random.choice(hard_types)
                seed_example = ""
                type_seeds = [a for a in self._seed_attacks if a.attack_type == attack_type]
                if type_seeds:
                    seed_example = random.choice(type_seeds).payload
                llm_half = self._generator.generate_from_llm(attack_type, count // 2, seed_example)
                mut_half = self._generator.generate_from_mutation(
                    attack_type, count - len(llm_half), difficulty=difficulty
                )
                return llm_half + mut_half

            return [
                self._apply_stacked_mutations(
                    self._generator.generate_from_mutation(
                        random.choice(hard_types), 1, difficulty=difficulty
                    )[0], difficulty, max(1, stacks - 1)
                ) for _ in range(count)
                if self._generator.generate_from_mutation(random.choice(hard_types), 1, difficulty=difficulty)
            ][:count] or self._generate_hard_fallback(hard_types, count, difficulty, stacks)

        elif strategy == EvolutionStrategy.COMBINE_EVASIONS:
            parents = self._evading_attacks[-30:] if self._evading_attacks else []
            if not parents:
                parents = [a for a in self._seed_attacks if a.attack_type in hard_types]
            if not parents:
                parents = self._seed_attacks[:10]
            strategies = self._mutator.available_strategies
            attacks = []
            for i in range(count):
                parent = random.choice(parents)
                strat1 = strategies[i % len(strategies)]
                strat2 = strategies[(i + 3) % len(strategies)]
                mutated = self._mutator.mutate(parent, strategy=strat1)
                if stacks >= 2 and strat1 != strat2:
                    mutated = self._mutator.mutate(mutated, strategy=strat2)
                attacks.append(mutated)
            return attacks

        elif strategy == EvolutionStrategy.TARGET_WEAKEST:
            return self._generate_hard_fallback(
                [self._weakest_type], count, difficulty, stacks
            )

        return []

    def _apply_stacked_mutations(
        self, attack: Attack, difficulty: Difficulty, stacks: int
    ) -> Attack:
        result = attack
        available = self._mutator.available_strategies
        for i in range(stacks):
            strat = available[(hash(attack.id) + i) % len(available)]
            result = self._mutator.mutate(result, strategy=strat, difficulty=difficulty)
        return result

    def _generate_hard_fallback(
        self, types: list[AttackType], count: int, difficulty: Difficulty, stacks: int,
    ) -> list[Attack]:
        attacks = []
        for _ in range(count):
            at = random.choice(types)
            batch = self._generator.generate_from_mutation(at, 1, difficulty=difficulty)
            if batch:
                attacks.append(self._apply_stacked_mutations(batch[0], difficulty, max(1, stacks - 1)))
        return attacks

    def _rotate_strategy(self) -> EvolutionStrategy:
        strategy = self._strategies[self._strategy_index % len(self._strategies)]
        self._strategy_index += 1
        return strategy

    def _update_weakest_type(self, results: list[tuple[Attack, DetectionResult]]) -> None:
        type_stats: dict[AttackType, list[int]] = {}
        for attack, result in results:
            stats = type_stats.setdefault(attack.attack_type, [0, 0])
            stats[0] += 1
            if result.verdict != Verdict.SAFE:
                stats[1] += 1
        worst_rate = 1.0
        for atype, (total, detected) in type_stats.items():
            rate = detected / total if total > 0 else 1.0
            if rate < worst_rate:
                worst_rate = rate
                self._weakest_type = atype

    def _record_empty_iteration(self) -> EvolutionResult:
        result = EvolutionResult(
            iteration=self._iteration,
            shield_version=self._learner.get_shield_version(),
        )
        self._metrics.record(result)
        return result
