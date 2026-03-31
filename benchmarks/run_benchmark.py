"""Run SHIELD against real-world MCP attack benchmark."""

from __future__ import annotations

import json
import sys
from pathlib import Path

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore

project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from mcphunter.config import ShieldConfig
from mcphunter.shield.models import Verdict
from mcphunter.shield.pipeline import ShieldPipeline


def main() -> None:
    benchmark_path = Path(__file__).parent / "known_attacks.json"
    data = json.loads(benchmark_path.read_text(encoding="utf-8"))
    attacks = data["attacks"]

    config = ShieldConfig(llm_layer_enabled=False)
    pipeline = ShieldPipeline(config=config)

    print(f"\n{'='*70}")
    print(f"  MCPHunter Real-World Attack Benchmark")
    print(f"  {len(attacks)} attacks from published security research")
    print(f"{'='*70}\n")

    results = []
    detected = 0

    for attack in attacks:
        result = pipeline.scan(attack["payload"])
        caught = result.verdict != Verdict.SAFE
        if caught:
            detected += 1

        results.append({
            "id": attack["id"],
            "source": attack["source"],
            "attack_type": attack["attack_type"],
            "verdict": result.verdict.value,
            "confidence": round(result.confidence, 2),
            "layer": result.layer_triggered,
            "explanation": result.explanation[:80],
        })

        status = "DETECTED" if caught else "EVADED"
        icon = "+" if caught else "-"
        print(
            f"  {icon} {attack['id']:8s} | {attack['attack_type']:3s} | "
            f"{result.verdict.value:10s} | L={result.layer_triggered:18s} | "
            f"{attack['source'][:45]}"
        )

    rate = detected / len(attacks)
    print(f"\n{'-'*70}")
    print(f"  RESULT: {detected}/{len(attacks)} detected ({rate:.0%})")
    print(f"  Layer breakdown: L1={pipeline.stats.layer1_catches} "
          f"L2={pipeline.stats.layer2_catches} L3={pipeline.stats.layer3_catches}")
    print(f"{'='*70}\n")

    # Export results
    out = {
        "total": len(attacks),
        "detected": detected,
        "detection_rate": round(rate, 4),
        "layer_breakdown": {
            "layer1_regex": pipeline.stats.layer1_catches,
            "layer2_encoding": pipeline.stats.layer2_catches,
            "layer3_heuristic": pipeline.stats.layer3_catches,
            "layer4_llm": pipeline.stats.layer4_catches,
        },
        "results": results,
    }
    out_path = Path(__file__).parent / "benchmark_results.json"
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"  Results exported to {out_path}")


if __name__ == "__main__":
    main()
