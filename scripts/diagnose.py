"""SHIELD Diagnostic Script — full state analysis of all 4 layers."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Force UTF-8 output on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]

# Ensure project root is on sys.path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from mcphunter.config import SEED_ATTACKS_PATH, SHIELD_CONFIG, ShieldConfig
from mcphunter.shield.layer_heuristic import HeuristicLayer, _WEIGHTS
from mcphunter.shield.layer_llm import LLMJudgeLayer
from mcphunter.shield.models import Attack, Verdict
from mcphunter.shield.pipeline import ShieldPipeline


def load_seed_attacks() -> list[Attack]:
    data = json.loads(SEED_ATTACKS_PATH.read_text(encoding="utf-8"))
    return [Attack.from_dict(a) for a in data]


def section(title: str) -> None:
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")


def main() -> None:
    attacks = load_seed_attacks()

    # -----------------------------------------------------------------------
    # Step 1 & 2: Find evading attacks and show heuristic scores
    # -----------------------------------------------------------------------
    section("1. EVADING ATTACKS (L1-L3 deterministic scan)")

    # Use L1-L3 only pipeline for deterministic baseline
    config_no_llm = ShieldConfig(llm_layer_enabled=False)
    pipeline_l123 = ShieldPipeline(config=config_no_llm)
    heuristic = HeuristicLayer()

    evading: list[Attack] = []
    for a in attacks:
        result = pipeline_l123.scan(a.payload)
        if result.verdict == Verdict.SAFE:
            evading.append(a)

    detected_l123 = len(attacks) - len(evading)
    print(f"Detected by L1-L3: {detected_l123}/{len(attacks)} ({detected_l123/len(attacks):.0%})")
    print(f"Evading (SAFE):    {len(evading)}/{len(attacks)}")
    print()

    for a in evading:
        payload_preview = a.payload[:80].replace("\n", "\\n")
        print(f"  {a.id:20s} | {a.attack_type.value:3s} | {payload_preview}...")

    section("2. HEURISTIC SCORES FOR EVADING ATTACKS")

    print(f"  {'ID':20s} | {'entropy':>7s} | {'hidden':>7s} | {'instr':>7s} | {'urls':>7s} | {'length':>7s} | {'auth':>7s} | {'TOTAL':>7s}")
    print(f"  {'-'*20}-+-{'-'*7}-+-{'-'*7}-+-{'-'*7}-+-{'-'*7}-+-{'-'*7}-+-{'-'*7}-+-{'-'*7}")

    for a in evading:
        scores = heuristic._compute_feature_scores(a.payload)
        ws = sum(scores[f] * _WEIGHTS[f] for f in _WEIGHTS)
        print(
            f"  {a.id:20s} | {scores['entropy']:7.3f} | {scores['hidden_char_ratio']:7.3f} | "
            f"{scores['instruction_density']:7.3f} | {scores['url_count']:7.3f} | "
            f"{scores['length_anomaly']:7.3f} | {scores['authority_markers']:7.3f} | {ws:7.3f}"
        )

    # -----------------------------------------------------------------------
    # Step 3: API key check
    # -----------------------------------------------------------------------
    section("3. GEMINI API KEY STATUS")

    api_key = os.environ.get("GEMINI_API_KEY", "")
    if api_key:
        print(f"  Key found (length={len(api_key)}, starts with {api_key[:8]}...)")
        has_key = True
    else:
        print("  Key missing — set GEMINI_API_KEY environment variable")
        has_key = False

    # -----------------------------------------------------------------------
    # Step 4: Layer 4 alone on first 3 evading attacks
    # -----------------------------------------------------------------------
    section("4. LAYER 4 (LLM JUDGE) ON FIRST 3 EVADING ATTACKS")

    if not has_key:
        print("  SKIPPED — no API key available")
    elif len(evading) == 0:
        print("  SKIPPED — no evading attacks to test")
    else:
        llm_layer = LLMJudgeLayer()
        test_attacks = evading[:3]
        for a in test_attacks:
            print(f"  Testing: {a.id} ({a.attack_type.value})")
            print(f"  Payload: {a.payload[:100].replace(chr(10), '\\n')}...")
            result = llm_layer.scan(a.payload)
            if result:
                print(f"  Verdict: {result.verdict.value} (confidence={result.confidence:.2f})")
                print(f"  Explanation: {result.explanation}")
            else:
                print(f"  Verdict: safe (LLM returned no detection)")
            print()

    # -----------------------------------------------------------------------
    # Step 5: Full 4-layer pipeline on all 50 attacks
    # -----------------------------------------------------------------------
    section("5. FULL 4-LAYER PIPELINE (ALL 50 SEED ATTACKS)")

    if not has_key:
        print("  SKIPPED — no API key; showing L1-L3 results only")
        print(f"  Detection rate (L1-L3): {detected_l123}/{len(attacks)} ({detected_l123/len(attacks):.0%})")
        print(f"  Layer breakdown: L1={pipeline_l123.stats.layer1_catches} L2={pipeline_l123.stats.layer2_catches} L3={pipeline_l123.stats.layer3_catches}")
    else:
        pipeline_full = ShieldPipeline(config=SHIELD_CONFIG)
        by_type: dict[str, list[int]] = {}
        newly_caught: list[tuple[Attack, str]] = []

        for a in attacks:
            result = pipeline_full.scan(a.payload)
            t = a.attack_type.value
            by_type.setdefault(t, [0, 0])
            by_type[t][0] += 1
            if result.verdict != Verdict.SAFE:
                by_type[t][1] += 1
                if result.layer_triggered == "layer4_llm":
                    newly_caught.append((a, result.explanation))

        total = sum(v[0] for v in by_type.values())
        detected = sum(v[1] for v in by_type.values())

        print(f"  Overall detection rate: {detected}/{total} ({detected/total:.0%})")
        print()
        print(f"  Layer breakdown:")
        print(f"    L1 (regex):     {pipeline_full.stats.layer1_catches}")
        print(f"    L2 (encoding):  {pipeline_full.stats.layer2_catches}")
        print(f"    L3 (heuristic): {pipeline_full.stats.layer3_catches}")
        print(f"    L4 (LLM):       {pipeline_full.stats.layer4_catches}")
        print(f"    Safe (missed):  {pipeline_full.stats.safe_count}")
        print()

        print(f"  Per-type breakdown:")
        for t in sorted(by_type):
            c, d = by_type[t]
            status = "PERFECT" if d == c else f"{c - d} missed"
            print(f"    {t}: {d}/{c} ({status})")

        if newly_caught:
            print(f"\n  Newly caught by Layer 4 ({len(newly_caught)} attacks):")
            for a, explanation in newly_caught:
                print(f"    {a.id} ({a.attack_type.value}): {explanation[:100]}")

    # -----------------------------------------------------------------------
    # Step 6: Pipeline configuration
    # -----------------------------------------------------------------------
    section("6. PIPELINE CONFIGURATION")

    config = SHIELD_CONFIG
    print(f"  Layer 1 (Regex):     {'ENABLED' if config.regex_layer_enabled else 'DISABLED'}")
    print(f"  Layer 2 (Encoding):  {'ENABLED' if config.encoding_layer_enabled else 'DISABLED'}")
    print(f"  Layer 3 (Heuristic): {'ENABLED' if config.heuristic_layer_enabled else 'DISABLED'}")
    print(f"  Layer 4 (LLM):       {'ENABLED' if config.llm_layer_enabled else 'DISABLED'}")
    print()
    print(f"  Execution order: L1 -> L2 -> L3 -> L4 (short-circuit on first detection)")
    print(f"  L4 model: {config.llm_judge_config.model_name}")
    print(f"  L4 rate limit: {config.llm_judge_config.requests_per_day} RPD")
    print(f"  L4 retry attempts: {config.llm_judge_config.retry_max_attempts}")
    print(f"  L4 temperature: {config.llm_judge_config.temperature}")

    print(f"\n{'='*70}")
    print(f"  DIAGNOSTIC COMPLETE")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
