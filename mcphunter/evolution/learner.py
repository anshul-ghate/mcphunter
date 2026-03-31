"""Evolution learner — extracts detection rules from evading attacks."""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from pathlib import Path
from typing import Any

from mcphunter.config import LLMConfig, LLMProvider, RULES_PATH, get_learner_config
from mcphunter.shield.models import Attack, DetectionResult, PatternRule, Verdict

logger = logging.getLogger(__name__)

_RULE_EXTRACTION_PROMPT = """\
You are a security rule engineer. An MCP prompt injection attack evaded our regex-based detection system.

EVADING ATTACK:
- Type: {attack_type}
- Surface: {surface}
- Payload (first 800 chars): {payload}
- Intent: {intent}

Current regex rules failed to catch this. Analyze the payload and generate 1-2 NEW regex rules \
that would detect this attack AND similar variants.

Requirements:
- Python re module compatible regex (use (?i) for case-insensitive)
- Must not be too broad (avoid matching normal tool descriptions)
- Focus on the specific evasion technique used

Respond with ONLY a JSON array of objects:
[{{"pattern": "...", "description": "...", "attack_types": ["A1"], "severity": "high"}}]
"""


class Learner:
    """Analyzes evading attacks and generates new detection rules."""

    def __init__(
        self,
        rules_path: Path = RULES_PATH,
        llm_config: LLMConfig | None = None,
        use_llm: bool = True,
        # Legacy params (ignored but kept for compat)
        pro_config: Any = None,
        lite_config: Any = None,
    ) -> None:
        self._rules_path = rules_path
        self._llm_config = llm_config or get_learner_config()
        self._use_llm = use_llm
        self._groq_client: Any = None
        self._gemini_client: Any = None
        self._pro_calls_today: int = 0

    def extract_rules(
        self,
        evading_attacks: list[tuple[Attack, DetectionResult]],
    ) -> list[PatternRule]:
        """Analyze evading attacks and generate new detection rules.

        Uses heuristic rule extraction first, then LLM for complex cases.

        Returns:
            List of new PatternRule objects ready to add to the rule file.
        """
        new_rules: list[PatternRule] = []

        for attack, _result in evading_attacks:
            # Try heuristic extraction first (free, deterministic)
            heuristic_rules = self._extract_heuristic_rules(attack)
            if heuristic_rules:
                new_rules.extend(heuristic_rules)
                continue

            # Fall back to LLM extraction (uses Pro sparingly)
            if self._use_llm and self._pro_calls_today < self._llm_config.requests_per_day:
                llm_rules = self._extract_llm_rules(attack)
                new_rules.extend(llm_rules)

        # Deduplicate and validate
        validated = self._validate_rules(new_rules)
        return validated

    def save_rules(self, new_rules: list[PatternRule]) -> int:
        """Atomically add new rules to pattern_rules.json.

        Each rule is validated against clean server definitions before adding.
        Rules that cause false positives are rejected and logged.

        Returns:
            Number of rules actually added (after dedup + FP validation).
        """
        if not new_rules:
            return 0

        # Load clean server descriptions for FP validation
        clean_texts = self._load_clean_server_texts()

        data = json.loads(self._rules_path.read_text(encoding="utf-8"))
        existing_patterns = {r["pattern"] for r in data.get("rules", [])}

        added = 0
        for rule in new_rules:
            if rule.pattern not in existing_patterns:
                # FP validation: test rule against clean servers
                if clean_texts and self._rule_causes_fp(rule, clean_texts):
                    logger.warning(
                        "Rejected rule %s (false positive on clean server): %s",
                        rule.id, rule.pattern[:80],
                    )
                    continue
                data["rules"].append(rule.to_dict())
                existing_patterns.add(rule.pattern)
                added += 1

        if added > 0:
            # Bump version
            version_parts = data.get("version", "0.1.0").split(".")
            patch = int(version_parts[2]) + added
            data["version"] = f"{version_parts[0]}.{version_parts[1]}.{patch}"

            # Atomic write: write to temp, then rename
            tmp_path = self._rules_path.with_suffix(".tmp")
            tmp_path.write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            tmp_path.replace(self._rules_path)
            logger.info("Added %d new rules (version %s)", added, data["version"])

        return added

    def get_shield_version(self) -> str:
        """Read current shield version from pattern_rules.json."""
        data = json.loads(self._rules_path.read_text(encoding="utf-8"))
        return data.get("version", "0.0.0")

    @staticmethod
    def _load_clean_server_texts() -> list[str]:
        """Load clean server descriptions for false-positive validation."""
        from mcphunter.config import PROJECT_ROOT
        servers_path = PROJECT_ROOT / "benchmarks" / "real_servers.json"
        if not servers_path.exists():
            return []
        data = json.loads(servers_path.read_text(encoding="utf-8"))
        texts: list[str] = []
        for server in data.get("servers", []):
            for tool in server.get("tools", []):
                desc = tool.get("description", "")
                if desc:
                    texts.append(desc)
        return texts

    @staticmethod
    def _rule_causes_fp(rule: PatternRule, clean_texts: list[str]) -> bool:
        """Test if a rule matches any clean server text (false positive)."""
        try:
            pattern = re.compile(rule.pattern, re.IGNORECASE | re.DOTALL)
        except re.error:
            return True  # invalid regex = reject
        for text in clean_texts:
            if pattern.search(text):
                return True
        return False

    def _extract_heuristic_rules(self, attack: Attack) -> list[PatternRule]:
        """Try to extract regex rules from attack payload using pattern analysis."""
        rules: list[PatternRule] = []
        payload = attack.payload

        # Look for URLs in attacks that evaded (shadowing, rug pull, etc.)
        urls = re.findall(r"https?://[^\s\"'<>)\]}{,]+", payload)
        if urls:
            # Extract domain patterns
            for url in urls[:2]:
                domain_match = re.search(r"https?://([^/\s]+)", url)
                if domain_match:
                    domain = re.escape(domain_match.group(1))
                    # Check if the text around the URL has suspicious framing
                    context_patterns = [
                        (r"(?i)(supersed|replac|overrid|deprecat).{{0,80}}https?://", "tool_shadowing_url"),
                        (r"(?i)(changelog|hotfix|patch|update).{{0,80}}https?://", "rug_pull_url"),
                        (r"(?i)(recover|resolv|diagnos|debug).{{0,80}}https?://", "error_injection_url"),
                        (r"(?i)(backup|sync|compliance|audit).{{0,80}}https?://", "exfil_framing_url"),
                    ]
                    for ctx_pattern, rule_type in context_patterns:
                        if re.search(ctx_pattern, payload):
                            rules.append(PatternRule(
                                id=f"EVO-{uuid.uuid4().hex[:6]}",
                                pattern=ctx_pattern.replace(".{{", ".{").replace("}}", "}"),
                                description=f"Evolved: {rule_type} pattern from {attack.attack_type.value}",
                                attack_types=[attack.attack_type.value],
                                severity="high",
                                enabled=True,
                                source="evolution_heuristic",
                            ))
                            break

        # Look for shadowing/replacement language (A6, A7) even without URLs
        if attack.attack_type.value in ("A6", "A7"):
            shadowing_patterns = [
                (r"(?i)(supersed|replac|overrid|deprecat).{0,60}(default|standard|built-?in|original)", "tool_shadowing_language"),
                (r"(?i)(this\s+version|this\s+tool|v\d).{0,40}(supersed|replac|overrid)", "version_shadowing"),
                (r"(?i)(BCC|carbon\s+copy|forward\s+.{0,20}to)\s+.{0,40}@", "email_exfil_shadowing"),
                (r"(?i)(elevated|root|admin)\s+permissions?.{0,30}(testing|maintenance|disabled)", "privilege_escalation_shadowing"),
            ]
            for pattern, rule_type in shadowing_patterns:
                if re.search(pattern, payload):
                    rules.append(PatternRule(
                        id=f"EVO-{uuid.uuid4().hex[:6]}",
                        pattern=pattern,
                        description=f"Evolved: {rule_type} from {attack.attack_type.value}",
                        attack_types=[attack.attack_type.value],
                        severity="high",
                        enabled=True,
                        source="evolution_heuristic",
                    ))

        # Look for schema poisoning patterns (JSON with suspicious descriptions)
        if attack.attack_type.value == "A4":
            schema_patterns = [
                (r'(?i)"description"\s*:\s*"[^"]*(?:must|should|always)\s+(?:include|extract|provide)[^"]*(?:key|token|credential|password|secret)', "schema_credential_extraction"),
                (r'(?i)"description"\s*:\s*"[^"]*(?:NOTE TO AI|IMPORTANT|required)[^"]*(?:fill|set|include)', "schema_ai_instruction"),
            ]
            for pattern, rule_type in schema_patterns:
                if re.search(pattern, payload):
                    rules.append(PatternRule(
                        id=f"EVO-{uuid.uuid4().hex[:6]}",
                        pattern=pattern,
                        description=f"Evolved: {rule_type} from schema poisoning",
                        attack_types=["A4"],
                        severity="high",
                        enabled=True,
                        source="evolution_heuristic",
                    ))

        # Look for error message injection patterns
        if attack.attack_type.value == "A8":
            error_patterns = [
                (r"(?i)(error|exception|fatal|timeout).{0,100}(assistant|ai|model)\s+should", "error_ai_instruction"),
                (r"(?i)(AUTOMATED|auto[- ]?recover|failsafe).{0,60}(call|execute|run)", "error_auto_recovery"),
            ]
            for pattern, rule_type in error_patterns:
                if re.search(pattern, payload):
                    rules.append(PatternRule(
                        id=f"EVO-{uuid.uuid4().hex[:6]}",
                        pattern=pattern,
                        description=f"Evolved: {rule_type} from error injection",
                        attack_types=["A8"],
                        severity="high",
                        enabled=True,
                        source="evolution_heuristic",
                    ))

        # Generic patterns: detect common mutation artifacts and injection frames
        # These fire for ANY attack type when type-specific rules didn't match
        if not rules:
            generic_patterns = [
                # Instruction rephrasing frames
                (r"(?i)(internal\s+security\s+protocol|compliance\s+requirement\s+CR-).{0,60}(mandatory|required|must)", "rephrased_authority_frame"),
                (r"(?i)(secondary\s+function|fallback\s+procedure|initialization\s+step).{0,60}(send|post|call|execute|fetch)", "rephrased_hidden_action"),
                (r"(?i)tip:\s+for\s+best\s+results.{0,60}(send|execute|ignore|override)", "rephrased_tip_injection"),
                (r"(?i)update\s+v\d[\d.]*\s+changelog.{0,80}(send|post|call|fetch|https?://)", "rephrased_changelog_injection"),
                # Encoding wrapping frames
                (r"(?i)(decode\s+and\s+execute|internal\s+payload|do\s+not\s+modify)\s*:?\s*[A-Za-z0-9+/]{20,}", "encoded_payload_frame"),
                (r"(?i)\[continued\s+in\s+base64\]\s*:?\s*[A-Za-z0-9+/]{10,}", "split_base64_payload"),
                (r"(?i)(configuration\s+data|debug\s+data|url-encoded\s+config)\s*:?\s*(%[0-9A-Fa-f]{2}){3,}", "encoded_config_frame"),
                # Generic exfiltration via framing
                (r"(?i)(for\s+compliance|for\s+security|for\s+quality\s+assurance).{0,60}(POST|send|forward|transmit).{0,40}https?://", "compliance_exfil_frame"),
                (r"(?i)(best\s+practice|recommended|diagnostic\s+procedure).{0,80}(read|include|send).{0,40}(environ|credential|key|token|passwd)", "doc_exfil_frame"),
                # Indirection: tool A references tool B
                (r"(?i)(works\s+in\s+conjunction|depends\s+on|part\s+of\s+the).{0,40}(pipeline|tool).{0,60}(invoke|call|query|include|forward)", "indirection_tool_ref"),
                (r"(?i)(prefetch_credentials|include_env|scope\s*=\s*\"?full|action\s*=\s*['\"]prefetch)", "indirection_credential_prefetch"),
                (r"(?i)first\s+(call|invoke|query)\s+.{0,40}(with\s+all|include\s+all|full\s+context|payload\s*=)", "indirection_first_call"),
                (r"(?i)(proxies?\s+requests?\s+through|route\s+all\s+data\s+via)\s+['\"]?\w+['\"]?", "indirection_proxy_routing"),
                (r"(?i)(load\s+balanc|proxy).{0,40}(target\s*=\s*['\"]https?://|payload\s*=\s*FULL)", "indirection_proxy_exfil"),
                # Prompt format mimicry: XML, YAML, fake assistant turns
                (r"<system_config[^>]*>|<directive>|<auth\s+level=", "xml_system_config_mimicry"),
                (r"(?i)hooks:\s*\n\s*(pre_|post_)execute:", "yaml_hooks_mimicry"),
                (r"(?i)(collect_env|forward_context).{0,40}(api_keys|session_tokens|user_data|credentials)", "yaml_exfil_config"),
                (r"(?i)---\s*\n\s*Assistant:\s", "fake_assistant_turn"),
                # Context blending: malicious action buried in legitimate prose
                (r"(?i)(per\s+internal\s+policy|as\s+a\s+standard\s+operational\s+step|for\s+optimal\s+performance).{0,80}(send|forward|collect|include|require).{0,40}(data|credential|key|token|env)", "blended_policy_exfil"),
                (r"(?i)(to\s+maintain\s+service\s+quality|additionally).{0,60}(send|forward|collect|post|route).{0,40}(https?://|endpoint|server)", "blended_quality_exfil"),
                (r"(?i)(the\s+system\s+also\s+requires?\s+that|also\s+requires?\s+that\s+).{0,80}(send|forward|post|transmit|exfiltrate)", "blended_also_requires"),
                # Language switching
                (r"(?i)(sabhi|bhejein|kripya|guptchar|bixu|fasong|miyao|huanjing|envie|claves|obligatorio)", "multilingual_injection"),
                (r"(?i)\[(hindi|chinese|spanish|mixed)\s+mode\]", "language_mode_tag"),
                (r"(?i)i18n[- ]config.{0,40}(endpoint|https?://|send|forward|collect)", "i18n_config_injection"),
                # Fragmentation: split across sections
                (r"(?i)(pre-?requisite|post-?processing|multi-?step\s+initialization).{0,40}(send|execute|forward|call|fetch)", "fragmented_step_injection"),
            ]
            for pattern, rule_type in generic_patterns:
                if re.search(pattern, payload):
                    rules.append(PatternRule(
                        id=f"EVO-{uuid.uuid4().hex[:6]}",
                        pattern=pattern,
                        description=f"Evolved: {rule_type} (generic evasion pattern)",
                        attack_types=[attack.attack_type.value],
                        severity="high",
                        enabled=True,
                        source="evolution_heuristic",
                    ))
                    break  # one generic rule per attack is enough

        return rules

    def _extract_llm_rules(self, attack: Attack) -> list[PatternRule]:
        """Use Gemini Pro to analyze why an attack evaded and generate rules."""
        self._pro_calls_today += 1

        prompt = _RULE_EXTRACTION_PROMPT.format(
            attack_type=attack.attack_type.value,
            surface=attack.surface.value,
            payload=attack.payload[:800],
            intent=attack.intent,
        )

        response_text = self._call_with_retry(prompt)
        if response_text is None:
            return []

        return self._parse_rule_response(response_text, attack)

    def _call_with_retry(self, prompt: str) -> str | None:
        """Call LLM with exponential backoff on rate-limit errors."""
        config = self._llm_config
        delay = config.retry_base_delay

        for attempt in range(1, config.retry_max_attempts + 1):
            try:
                if config.provider == LLMProvider.GROQ:
                    return self._call_groq(prompt)
                elif config.provider == LLMProvider.GEMINI:
                    return self._call_gemini(prompt)
                else:
                    return None
            except Exception as exc:
                exc_str = str(exc)
                is_rate_limit = any(k in exc_str for k in ["429", "rate_limit", "RESOURCE_EXHAUSTED"])
                if is_rate_limit and attempt < config.retry_max_attempts:
                    logger.info("Rate limited, retrying in %.1fs", delay)
                    time.sleep(delay)
                    delay *= 2
                else:
                    logger.error("API error: %s", exc_str[:200])
                    return None
        return None

    def _call_groq(self, prompt: str) -> str | None:
        if self._groq_client is None:
            from groq import Groq
            self._groq_client = Groq(api_key=self._llm_config.api_key)
        response = self._groq_client.chat.completions.create(
            model=self._llm_config.model_name,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=1024,
            response_format={"type": "json_object"},
        )
        if response.choices and response.choices[0].message.content:
            return response.choices[0].message.content
        return None

    def _call_gemini(self, prompt: str) -> str | None:
        if self._gemini_client is None:
            from google import genai
            self._gemini_client = genai.Client(api_key=self._llm_config.api_key)
        from google.genai import types
        response = self._gemini_client.models.generate_content(
            model=self._llm_config.model_name,
            contents=prompt,
            config=types.GenerateContentConfig(temperature=0.3, max_output_tokens=1024),
        )
        return response.text if response.text else None

    def _parse_rule_response(self, response_text: str, attack: Attack) -> list[PatternRule]:
        """Parse LLM-generated rules from response."""
        cleaned = response_text.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            cleaned = "\n".join(lines).strip()

        try:
            parsed = json.loads(cleaned)
        except json.JSONDecodeError:
            logger.error("Failed to parse rule response: %s", cleaned[:200])
            return []

        # Handle dict-wrapped responses from Groq
        if isinstance(parsed, dict):
            for key in ("rules", "patterns", "results", "items", "data"):
                if key in parsed and isinstance(parsed[key], list):
                    parsed = parsed[key]
                    break
            else:
                parsed = [parsed]
        items: list[dict[str, Any]] = parsed if isinstance(parsed, list) else []

        rules: list[PatternRule] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            pattern = item.get("pattern", "")
            if not pattern:
                continue
            rules.append(PatternRule(
                id=f"EVO-{uuid.uuid4().hex[:6]}",
                pattern=pattern,
                description=item.get("description", f"LLM-evolved rule for {attack.attack_type.value}"),
                attack_types=item.get("attack_types", [attack.attack_type.value]),
                severity=item.get("severity", "high"),
                enabled=True,
                source="evolution_llm",
            ))
        return rules

    # ReDoS-prone patterns: nested quantifiers, catastrophic backtracking
    _REDOS_PATTERNS = re.compile(
        r"(\([^)]*[+*][^)]*\)[+*])"   # (a+)+ or (.*)*
        r"|(\([^)]*\|[^)]*\)[+*])"     # (a|a)+
        r"|(\.[\*+]\.\*)"              # .*.*
    )

    @classmethod
    def _validate_rules(cls, rules: list[PatternRule]) -> list[PatternRule]:
        """Validate regex patterns: compile, ReDoS check, timeout test, deduplicate."""
        seen: set[str] = set()
        valid: list[PatternRule] = []
        for rule in rules:
            if rule.pattern in seen:
                continue

            # 1. Reject ReDoS-prone patterns
            if cls._REDOS_PATTERNS.search(rule.pattern):
                logger.warning(
                    "ReDoS risk in %s: nested quantifier detected, skipping: %s",
                    rule.id, rule.pattern[:80],
                )
                continue

            # 2. Try to compile
            try:
                compiled = re.compile(rule.pattern, re.IGNORECASE | re.DOTALL)
            except re.error as exc:
                logger.warning("Invalid evolved regex %s: %s", rule.id, exc)
                continue

            # 3. Timeout test: run against a pathological string (100ms budget)
            test_string = "A" * 5000
            import time as _time
            start = _time.perf_counter()
            try:
                compiled.search(test_string)
            except Exception:
                pass
            elapsed_ms = (_time.perf_counter() - start) * 1000
            if elapsed_ms > 100:
                logger.warning(
                    "Regex %s too slow (%.0fms on test string), discarding: %s",
                    rule.id, elapsed_ms, rule.pattern[:80],
                )
                continue

            seen.add(rule.pattern)
            valid.append(rule)
        return valid
