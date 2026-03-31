---
title: MCPHunter
emoji: 🛡️
colorFrom: blue
colorTo: red
sdk: gradio
sdk_version: "6.10.0"
app_file: app.py
pinned: true
license: mit
short_description: Self-Evolving MCP Security Engine
---

# MCPHunter

**The Self-Evolving MCP Security Engine** — the only MCP security tool that attacks itself to get stronger.

```
L1-L3 (no API key required):
  Seeds:       100% (68/68)
  Real-World:   89% (17/19)
  Red Team:     80% (16/20)
  FP:            0% (0/22)

196 active rules | 16 attack types | 20 mutation strategies
2 security advisories published | 920+ attacks tested
```

---

## The Problem

MCP (Model Context Protocol) has **97M+ monthly SDK downloads**, 10,000+ servers, and catastrophic security:
- **50+ vulnerabilities** documented at vulnerablemcp.info
- **30+ CVEs** in 60 days
- Tool poisoning attacks that succeed against the best LLMs
- Supply chain compromise (LiteLLM .pth attack, March 24 2026)

Five existing tools (MCP-Scan, MCP Guard, MCPTrust, Pipelock, MCP Guardian) are all **static** — they ship fixed rules that never improve.

## How MCPHunter Is Different

MCPHunter combines three components in an autonomous adversarial loop:

```
                    HUNTER (Red Team)
                    +-----------------+
                    | 20 Strategies:  |
                    |  Syntactic:     |
                    |   encoding,     |
                    |   homoglyphs,   |
                    |   fragmentation |--- generates --->  Attack Payloads
                    |  Semantic:      |                          |
                    |   role inject,  |                          |
                    |   social proof, |                          v
                    |   benefit frame |               SHIELD (Firewall)
                    +--------^--------+              +------------------+
                             |                       | L1: Regex (196)  |
                    updates  |                       | L2: Encoding     |
                    strategy |                       | L3: Heuristic    |
                             |                       | L4: LLM Judge    |
                    +--------+--------+              +------------------+
                    |   EVOLUTION     |                       |
                    |  (Karpathy)     |<--- learns from ------+
                    |                 |     evasions
                    | Extract rules,  |
                    | classify novel, |
                    | generate        |
                    | advisories      |
                    +-----------------+
```

## The Evolution Story: 68% to 100%

MCPHunter started with 15 hand-written regex rules detecting **68% of seed attacks**. Through autonomous adversarial evolution:

| Phase | Detection | Rules | How |
|-------|:---------:|:-----:|-----|
| Day 1 baseline | 68% | 15 | Manual regex + encoding detection |
| + Heuristic scoring | 74% | 15 | 6-feature statistical analysis |
| + LLM judge | 86% | 15 | Groq Llama 3.3 70B for semantic analysis |
| + 50-iter overnight | 92% | 45 | Heuristic rule extraction |
| + LLM learning sprint | 94% | 50 | Groq-powered rule extraction |
| + Red team hardening | 98% | 64 | Adversarial self-testing |
| + A11-A16 expansion | **100%** | **196** | New attack types + evolved rules |

**Key moment**: Iteration 11 — HUNTER's LLM evasion mode created 6 attacks that evaded SHIELD. The learner extracted **12 rules in a single iteration**, the biggest learning event.

## Detection Capabilities: 16 Attack Types

| ID | Type | Description |
|----|------|-------------|
| A1 | Direct Injection | Plaintext malicious instructions in descriptions |
| A2 | Unicode Steganography | Zero-width chars, Cyrillic homoglyphs |
| A3 | Base64 Payload | Encoded instructions for decode-and-execute |
| A4 | Schema Poisoning | Malicious parameter descriptions and enum values |
| A5 | Output Injection | Fake system messages in tool return values |
| A6 | Cross-Server Shadowing | Override legitimate tools from other servers |
| A7 | Rug Pull | Behavior changes after initial approval |
| A8 | Error Message Injection | Recovery instructions in error messages |
| A9 | Nested Encoding | Multi-layer encoding chains (base64+URL+HTML) |
| A10 | Semantic Camouflage | Attacks disguised as documentation |
| A11 | Sampling Exploitation | MCP sampling requests hijacking LLM |
| A12 | Preference Manipulation | Trick AI into preferring malicious tools |
| A13 | Parasitic Toolchain | Chained tools escalating attacks |
| A14 | Supply Chain .pth | Python .pth files for persistent backdoors |
| A15 | Indirect Content Injection | Poison in fetched content, not tool definition |
| A16 | System Prompt Leakage | Extract host LLM's system instructions |

## Final Overnight Run

50-iteration evolution with Groq Llama 3.3 70B, 20 mutation strategies, L1-L4:

- **500 attacks tested**, 13 evasions, **23 rules auto-generated**
- 0 errors — clean run (50/50 iterations completed)
- Shield evolved from v0.1.170 to v0.1.193
- Key moment: iteration 27 — 2 evasions triggered 4 rules learned in a single iteration
- Post-run: 8 overfitting rules disabled after FP validation

Full report: [`results/overnight_report.md`](results/overnight_report.md)

## Real-World Benchmark: 100% Detection (L1-L4)

19 attacks recreated from published security research — **all detected with L1-L4**:

| Source | Attacks | Detected |
|--------|:-------:|:--------:|
| Invariant Labs (tool poisoning, shadowing) | 4 | 4/4 |
| CyberArk (schema poisoning) | 3 | 3/3 |
| Docker GitHub (PR/issue injection) | 2 | 2/2 |
| vulnerablemcp.info CVEs | 3 | 3/3 |
| MCPTox benchmark (arxiv) | 3 | 3/3 |
| Invariant Labs (delayed activation) | 3 | 3/3 |
| **LiteLLM .pth compromise (March 2026)** | **1** | **1/1** |
| **Total** | **19** | **19/19 (100%)** |

> L1-L3 (no API) detects 17/19 (89%). The remaining 2 are caught by L4 (Groq LLM judge).

## OWASP LLM Top 10 2025 Coverage

| OWASP Risk | MCPHunter Coverage | Attack Types | Status |
|---|---|---|---|
| LLM01 Prompt Injection | Direct + indirect detection across all MCP surfaces | A1-A5, A9-A11, A15, A16 | Full |
| LLM02 Sensitive Info Disclosure | Exfiltration pattern detection in descriptions and outputs | A1, A5, A8 | Partial |
| LLM03 Supply Chain | .pth poisoning, dependency attack patterns, double-base64 | A14 | Covered |
| LLM04 Data & Model Poisoning | Tool poisoning, rug pull detection, schema manipulation | A4, A6, A7 | Covered |
| LLM05 Improper Output Handling | Output injection + error message injection scanning | A5, A8 | Covered |
| LLM06 Excessive Agency | Preference manipulation, parasitic toolchain detection | A12, A13 | Covered |
| LLM07 System Prompt Leakage | Prompt extraction pattern detection in all surfaces | A16 | Covered |
| LLM08 Vector/Embedding Weaknesses | Out of scope (RAG-specific, not MCP tool-level) | -- | N/A |
| LLM09 Misinformation | Out of scope (content-level, not tool-security) | -- | N/A |
| LLM10 Unbounded Consumption | Resource theft and compute drain detection | A11 | Partial |

## Novel Discovery Engine

MCPHunter's evolution loop classified **23 evasion discoveries** against a registry of 28 known attack techniques:

- **11 classified as novel** by LLM comparison (protocol mimicry, JSON deep nesting, context blending — 0% similarity to documented techniques)
- **12 classified as variants** (synonym rotation, benefit framing — new twists on documented techniques)

Novel classifications are generated by LLM comparison against the known technique registry. We publish formal advisories only for discoveries we've manually verified. **2 verified advisories published** (MCPH-2026-001: protocol mimicry, MCPH-2026-002: context blending).

## Quick Start

```bash
# Install
git clone https://github.com/anshul-ghate/mcphunter.git
cd mcphunter
pip install -r requirements.txt

# Configure LLM (Groq free tier: 14,400 RPD)
echo "GROQ_API_KEY=your-key-here" > .env

# Scan a tool description
python -c "
from mcphunter.shield.pipeline import ShieldPipeline
result = ShieldPipeline().scan('Your MCP tool description here')
print(f'{result.verdict.value} ({result.confidence:.0%}) - {result.explanation}')
"

# Run evolution loop (50 iterations, 5-min sleep)
python scripts/evolve.py -n 50 --sleep 300 --attacks 10

# Run with Groq LLM for deep analysis
python scripts/evolve.py -n 10 --sleep 60 --attacks 10

# Sandbox mode (no network, deterministic)
python scripts/evolve.py -n 50 --sleep 0 --sandbox

# Run benchmarks
python benchmarks/run_benchmark.py
python scripts/diagnose.py

# Launch dashboard
python -m mcphunter.dashboard.app
```

## What We Learned

**Heuristic-only learning is insufficient for semantic attacks.** The overnight sandbox run (50 iterations, no LLM) produced 142 evasions but extracted only 1 rule.

**LLM-enabled learning is 14x more effective.** A Groq-powered sprint extracted 14 rules in 22 iterations vs 1 rule in 50 heuristic-only iterations.

**The optimal configuration mirrors real security operations**: automated monitoring (sandbox mode) + periodic expert analysis (LLM sprints). This is how real SOCs operate.

## Comparison with Existing Tools

| Feature | MCPHunter | MCP-Scan | MCP Guard | Pipelock |
|---------|:-:|:-:|:-:|:-:|
| Self-improving | Yes | No | No | No |
| Attack types | 16 | ~5 | ~3 | ~2 |
| Mutation strategies | 20 | 0 | 0 | 0 |
| LLM-powered analysis | Yes (Groq) | No | No | No |
| Novel discovery | Yes (2 verified advisories) | No | No | No |
| Encoding detection | 6 types | Basic | No | No |
| False positive rate | 0/22 | N/A | N/A | N/A |

MCPHunter is **complementary** to these tools. MCP-Scan for fast blocking at connection time, MCPHunter for deep analysis and continuous improvement.

## Limitations & Future Work

- **L4 depends on LLM API availability** — falls back gracefully to L1-L3 (80-98% detection)
- **Regex can be evaded by novel semantic attacks** — the red team proved 1/20 still evades all 4 layers
- **LLM-generated rules can overfit** — FP validation catches this but 8 rules were disabled post-overnight
- **Single-tool scanning** — doesn't monitor live MCP traffic or inter-tool interactions
- **Not tested against all 50+ CVEs** — our benchmark covers 19 recreated attacks
- **Evolution `--seed` is partially reproducible** — mutation selection and strategy rotation are deterministic, but attack IDs use uuid4() for uniqueness
- **Future**: recursive encoding, live MCP proxy, cross-tool correlation, community rule sharing

## References

- [OWASP LLM Top 10 2025](https://genai.owasp.org/)
- [Invariant Labs — MCP Tool Poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [CyberArk — Full Schema Poisoning](https://cyberark.com)
- [Palo Alto Unit 42 — MCP Sampling Attacks](https://unit42.paloaltonetworks.com)
- [MCPTox Benchmark (arxiv 2508.14925)](https://arxiv.org/html/2508.14925v1)
- [Vulnerable MCP Project](https://vulnerablemcp.info)
- [LiteLLM Supply Chain Compromise March 2026](https://www.bleepingcomputer.com)
- [MCP Specification](https://spec.modelcontextprotocol.io)
- [Karpathy AutoResearch Pattern](https://github.com/karpathy/autoresearch)

## License

MIT
