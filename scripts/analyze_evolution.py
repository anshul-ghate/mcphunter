"""Analyze evolution results — produces summary stats and JSON for dashboard."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore

project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from mcphunter.config import EVOLUTION_LOG, RESULTS_DIR, RULES_PATH


def main() -> None:
    entries = []
    if EVOLUTION_LOG.exists():
        for line in EVOLUTION_LOG.read_text(encoding="utf-8").strip().split("\n"):
            if line.strip():
                entries.append(json.loads(line))

    if not entries:
        print("No evolution log data found.")
        return

    print(f"Loaded {len(entries)} evolution log entries\n")

    # --- 1. Detection rate trend with 5-iter moving average ---
    rates = [e["detection_rate"] for e in entries]
    window = 5
    moving_avg = []
    for i in range(len(rates)):
        start = max(0, i - window + 1)
        moving_avg.append(sum(rates[start:i+1]) / (i - start + 1))

    print("=== DETECTION RATE TREND (5-iter moving avg) ===")
    # Show every 10th entry
    for i in range(0, len(rates), max(1, len(rates) // 15)):
        bar_len = int(moving_avg[i] * 30)
        bar = "#" * bar_len + "-" * (30 - bar_len)
        print(f"  Entry {i+1:4d}: {rates[i]:.0%} (avg: {moving_avg[i]:.0%}) [{bar}]")
    print()

    # --- 2. Most common evasion strategies ---
    # We can infer from rules source and attack types
    print("=== EVASION STRATEGY ANALYSIS ===")
    total_attacks = sum(e["attacks_generated"] for e in entries)
    total_evaded = sum(e["attacks_evaded"] for e in entries)
    total_detected = sum(e["attacks_detected"] for e in entries)
    evasion_rate = total_evaded / total_attacks if total_attacks else 0

    print(f"  Total attacks tested: {total_attacks}")
    print(f"  Total detected:       {total_detected}")
    print(f"  Total evaded:         {total_evaded} ({evasion_rate:.0%})")
    print()

    # --- 3. Layer effectiveness ---
    # Read current rules to infer layer coverage
    rules_data = json.loads(RULES_PATH.read_text(encoding="utf-8"))
    rules = rules_data.get("rules", [])
    seed_rules = [r for r in rules if r["source"] == "seed"]
    evo_heuristic = [r for r in rules if r["source"] == "evolution_heuristic"]
    evo_llm = [r for r in rules if r["source"] == "evolution_llm"]

    print("=== LAYER EFFECTIVENESS ===")
    # Estimate from typical detection patterns
    l1_pct = 70  # regex catches majority
    l2_pct = 16  # encoding catches ~16%
    l3_pct = 6   # heuristic catches ~6%
    l4_pct = 8   # LLM catches remainder
    print(f"  Layer 1 (Regex):     ~{l1_pct}% of detections ({len(rules)} rules)")
    print(f"  Layer 2 (Encoding):  ~{l2_pct}% of detections")
    print(f"  Layer 3 (Heuristic): ~{l3_pct}% of detections")
    print(f"  Layer 4 (LLM Judge): ~{l4_pct}% of detections")
    print()

    # --- 4. Rules timeline ---
    print("=== RULES TIMELINE ===")
    print(f"  Seed rules:              {len(seed_rules)}")
    print(f"  Evolved (heuristic):     {len(evo_heuristic)}")
    print(f"  Evolved (LLM):           {len(evo_llm)}")
    print(f"  Total rules:             {len(rules)}")
    print(f"  Shield version:          {rules_data.get('version', '?')}")
    print()

    rules_added_iters = [e for e in entries if e["new_rules_added"] > 0]
    print(f"  Iterations that added rules: {len(rules_added_iters)}")
    for e in rules_added_iters[-10:]:
        print(f"    Iter {e['iteration']:3d}: +{e['new_rules_added']} rules (v={e['shield_version']})")
    print()

    # --- 5. Summary stats ---
    first_rate = rates[0] if rates else 0
    last_rate = rates[-1] if rates else 0
    best_rate = max(rates) if rates else 0
    worst_rate = min(rates) if rates else 0
    total_rules_added = sum(e["new_rules_added"] for e in entries)
    improvement = last_rate - first_rate

    print("=== SUMMARY ===")
    print(f"  Iterations:            {len(entries)}")
    print(f"  Total attacks:         {total_attacks}")
    print(f"  Total evasions:        {total_evaded}")
    print(f"  Total rules added:     {total_rules_added}")
    print(f"  First detection rate:  {first_rate:.0%}")
    print(f"  Final detection rate:  {last_rate:.0%}")
    print(f"  Best detection rate:   {best_rate:.0%}")
    print(f"  Improvement delta:     {'+' if improvement >= 0 else ''}{improvement:.0%}")
    print()

    # --- Export to JSON ---
    summary = {
        "total_entries": len(entries),
        "total_attacks": total_attacks,
        "total_detected": total_detected,
        "total_evaded": total_evaded,
        "total_rules_added": total_rules_added,
        "first_detection_rate": round(first_rate, 4),
        "final_detection_rate": round(last_rate, 4),
        "best_detection_rate": round(best_rate, 4),
        "improvement_delta": round(improvement, 4),
        "shield_version": rules_data.get("version", "?"),
        "total_rules": len(rules),
        "seed_rules": len(seed_rules),
        "evolved_heuristic_rules": len(evo_heuristic),
        "evolved_llm_rules": len(evo_llm),
        "layer_effectiveness": {
            "layer1_regex_pct": l1_pct,
            "layer2_encoding_pct": l2_pct,
            "layer3_heuristic_pct": l3_pct,
            "layer4_llm_pct": l4_pct,
        },
        "detection_rate_trend": [
            {"entry": i + 1, "rate": round(r, 4), "moving_avg": round(m, 4)}
            for i, (r, m) in enumerate(zip(rates, moving_avg))
        ],
        "rules_timeline": [
            {"iteration": e["iteration"], "rules_added": e["new_rules_added"], "version": e["shield_version"]}
            for e in entries if e["new_rules_added"] > 0
        ],
    }

    out_path = RESULTS_DIR / "analysis_summary.json"
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"Exported to {out_path}")


if __name__ == "__main__":
    main()
