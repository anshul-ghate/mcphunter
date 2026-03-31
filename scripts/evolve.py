"""Evolution runner — starts the overnight Karpathy loop with safety guardrails."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]

project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from mcphunter.config import (
    EVOLUTION_CONFIG,
    EVOLUTION_LOG,
    RESULTS_DIR,
    RULES_PATH,
    ShieldConfig,
    EvolutionConfig,
)
from mcphunter.evolution.loop import EvolutionLoop

logger = logging.getLogger(__name__)

# Hard safety limits
MAX_ITERATIONS_HARD_CAP = 100
MAX_RULES_FILE_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_EVOLUTION_LOG_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_ATTACKS_LOG_BYTES = 100 * 1024 * 1024  # 100 MB


def check_disk_limits() -> list[str]:
    """Check file sizes against safety limits. Returns list of warnings."""
    warnings: list[str] = []

    if RULES_PATH.exists() and RULES_PATH.stat().st_size > MAX_RULES_FILE_BYTES:
        warnings.append(
            f"pattern_rules.json exceeds {MAX_RULES_FILE_BYTES // 1024 // 1024}MB limit "
            f"({RULES_PATH.stat().st_size // 1024 // 1024}MB)"
        )

    if EVOLUTION_LOG.exists() and EVOLUTION_LOG.stat().st_size > MAX_EVOLUTION_LOG_BYTES:
        rotated = EVOLUTION_LOG.with_name(
            f"{EVOLUTION_LOG.stem}_{EVOLUTION_LOG.stat().st_size // 1024 // 1024}mb{EVOLUTION_LOG.suffix}"
        )
        EVOLUTION_LOG.rename(rotated)
        warnings.append(f"evolution_log.jsonl rotated to {rotated.name}")

    attacks_log = RESULTS_DIR / "attacks.jsonl"
    if attacks_log.exists() and attacks_log.stat().st_size > MAX_ATTACKS_LOG_BYTES:
        rotated = attacks_log.with_name(
            f"{attacks_log.stem}_{attacks_log.stat().st_size // 1024 // 1024}mb{attacks_log.suffix}"
        )
        attacks_log.rename(rotated)
        warnings.append(f"attacks.jsonl rotated to {rotated.name}")

    return warnings


def print_banner(
    config: EvolutionConfig,
    shield_config: ShieldConfig,
    n: int,
    sandbox: bool,
) -> None:
    print()
    print("=" * 60)
    print("  MCPHunter Evolution Engine")
    print("  The Karpathy Loop: HUNTER attacks SHIELD, SHIELD learns")
    print("=" * 60)
    print()
    print(f"  Iterations:        {n} (hard cap: {MAX_ITERATIONS_HARD_CAP})")
    print(f"  Attacks/iter:      {config.attacks_per_iteration}")
    print(f"  Sleep between:     {config.sleep_seconds}s")
    print(f"  Target det. rate:  {config.target_detection_rate:.0%}")
    print(f"  Sandbox mode:      {'ON' if sandbox else 'OFF'}")
    print()
    print(f"  SHIELD layers:     L1={'ON' if shield_config.regex_layer_enabled else 'OFF'} "
          f"L2={'ON' if shield_config.encoding_layer_enabled else 'OFF'} "
          f"L3={'ON' if shield_config.heuristic_layer_enabled else 'OFF'} "
          f"L4={'ON' if shield_config.llm_layer_enabled else 'OFF'}")
    print()
    if sandbox:
        print("  SANDBOX: No network calls, no git, writes only to results/")
    print()
    print("  Windows overnight tip: disable sleep in Settings > Power,")
    print("  or run in a separate terminal:")
    print("    powershell -Command \"while(1){(New-Object -ComObject WScript.Shell).SendKeys('{F15}');Start-Sleep 240}\"")
    print()
    print("-" * 60)
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="MCPHunter Evolution Engine")
    parser.add_argument(
        "-n", "--iterations", type=int, default=50,
        help=f"Number of iterations (default: 50, hard cap: {MAX_ITERATIONS_HARD_CAP})",
    )
    parser.add_argument("--sleep", type=int, default=None, help="Seconds between iterations")
    parser.add_argument("--attacks", type=int, default=None, help="Attacks per iteration")
    parser.add_argument("--no-llm", action="store_true", help="Disable LLM calls (faster, deterministic)")
    parser.add_argument(
        "--sandbox", action="store_true",
        help="Sandbox mode: no network, no git, writes only to results/",
    )
    parser.add_argument("--resume", action="store_true", help="Resume from last checkpoint")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")
    args = parser.parse_args()

    # Enforce hard cap
    iterations = min(args.iterations, MAX_ITERATIONS_HARD_CAP)
    if args.iterations > MAX_ITERATIONS_HARD_CAP:
        print(f"  Warning: capped iterations from {args.iterations} to {MAX_ITERATIONS_HARD_CAP}")

    sleep_sec = args.sleep if args.sleep is not None else EVOLUTION_CONFIG.sleep_seconds
    attacks_per = args.attacks if args.attacks is not None else EVOLUTION_CONFIG.attacks_per_iteration

    evo_config = EvolutionConfig(
        attacks_per_iteration=attacks_per,
        sleep_seconds=sleep_sec,
        max_iterations=iterations,
    )

    # Sandbox forces no-llm
    use_llm = not args.no_llm and not args.sandbox
    shield_config = ShieldConfig(llm_layer_enabled=use_llm)

    print_banner(evo_config, shield_config, iterations, args.sandbox)

    # Pre-flight disk checks
    disk_warnings = check_disk_limits()
    for w in disk_warnings:
        print(f"  DISK WARNING: {w}")

    loop = EvolutionLoop(
        config=evo_config, shield_config=shield_config, random_seed=args.seed
    )

    try:
        loop.run(max_iterations=iterations, resume=args.resume)
    except KeyboardInterrupt:
        print("\n\n  Interrupted by user (Ctrl+C)")

    loop.metrics.print_final_summary()


if __name__ == "__main__":
    main()
