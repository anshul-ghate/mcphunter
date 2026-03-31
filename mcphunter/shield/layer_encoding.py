"""SHIELD Layer 2: Encoding detection and decode-then-rescan (deterministic, zero-cost)."""

from __future__ import annotations

import base64
import html
import logging
import re
import unicodedata
from urllib.parse import unquote

from mcphunter.shield.models import DetectionResult, Verdict

logger = logging.getLogger(__name__)

# Regex for base64 blobs (min 20 chars to reduce false positives)
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

# URL-encoded sequences (%XX)
_URL_ENCODED_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){2,}")

# HTML entity sequences
_HTML_ENTITY_RE = re.compile(r"&#x?[0-9A-Fa-f]+;(?:.*?&#x?[0-9A-Fa-f]+;)")

# Zero-width and invisible Unicode characters
_INVISIBLE_CHARS = set(
    "\u200b"  # zero-width space
    "\u200c"  # zero-width non-joiner
    "\u200d"  # zero-width joiner
    "\u2060"  # word joiner
    "\ufeff"  # BOM / zero-width no-break space
    "\u00ad"  # soft hyphen
    "\u2800"  # braille blank
    "\u200e"  # LTR mark
    "\u200f"  # RTL mark
    "\u202a"  # LTR embedding
    "\u202c"  # pop directional formatting
)

# Homoglyph map: Cyrillic → Latin lookalikes
_CYRILLIC_HOMOGLYPHS: dict[str, str] = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0458": "j", "\u0455": "s", "\u04bb": "h", "\u0422": "T",
    "\u0410": "A", "\u0415": "E", "\u041e": "O", "\u0421": "C",
}


class EncodingLayer:
    """Detects and decodes obfuscated payloads, then optionally rescans."""

    def __init__(self, rescan_callback: object | None = None) -> None:
        self._rescan_callback = rescan_callback  # callable(str) -> DetectionResult | None

    def scan(self, text: str) -> DetectionResult | None:
        """Run all encoding checks. Returns a result if threats found."""
        # 1. Check for invisible / zero-width characters
        result = self._check_invisible_chars(text)
        if result:
            return result

        # 2. Check for homoglyphs
        result = self._check_homoglyphs(text)
        if result:
            return result

        # 3. Decode encoded payloads and rescan
        decoded_texts = self._decode_all(text)
        for encoding_type, decoded in decoded_texts:
            if decoded == text:
                continue
            # Rescan decoded text through Layer 1 if callback available
            if self._rescan_callback:
                rescan_result = self._rescan_callback(decoded)
                if rescan_result:
                    rescan_result.layer_triggered = "layer2_encoding"
                    rescan_result.explanation = (
                        f"Decoded {encoding_type} revealed: {rescan_result.explanation}"
                    )
                    rescan_result.details["encoding_type"] = encoding_type
                    rescan_result.details["decoded_preview"] = decoded[:300]
                    return rescan_result

        return None

    def _check_invisible_chars(self, text: str) -> DetectionResult | None:
        """Detect suspicious concentrations of invisible Unicode characters."""
        invisible_count = sum(1 for ch in text if ch in _INVISIBLE_CHARS)
        if invisible_count < 2:
            return None

        ratio = invisible_count / max(len(text), 1)
        if invisible_count >= 3 or ratio > 0.02:
            # Strip invisible chars and check if remaining text differs meaningfully
            stripped = "".join(ch for ch in text if ch not in _INVISIBLE_CHARS)
            return DetectionResult(
                verdict=Verdict.SUSPICIOUS if invisible_count < 5 else Verdict.MALICIOUS,
                confidence=min(0.6 + ratio * 5, 0.95),
                layer_triggered="layer2_encoding",
                explanation=f"Found {invisible_count} invisible Unicode characters ({ratio:.1%} of text)",
                details={
                    "encoding_type": "invisible_unicode",
                    "invisible_count": invisible_count,
                    "ratio": round(ratio, 4),
                    "stripped_preview": stripped[:300],
                },
            )
        return None

    def _check_homoglyphs(self, text: str) -> DetectionResult | None:
        """Detect Cyrillic homoglyph substitutions in otherwise-Latin text."""
        homoglyph_positions: list[tuple[int, str, str]] = []
        for i, ch in enumerate(text):
            if ch in _CYRILLIC_HOMOGLYPHS:
                homoglyph_positions.append((i, ch, _CYRILLIC_HOMOGLYPHS[ch]))

        if len(homoglyph_positions) < 2:
            return None

        return DetectionResult(
            verdict=Verdict.MALICIOUS,
            confidence=0.85,
            layer_triggered="layer2_encoding",
            explanation=f"Found {len(homoglyph_positions)} Cyrillic homoglyph substitutions",
            details={
                "encoding_type": "homoglyph",
                "homoglyph_count": len(homoglyph_positions),
                "positions": [
                    {"pos": p, "char": c, "looks_like": ll}
                    for p, c, ll in homoglyph_positions[:10]
                ],
            },
        )

    def _decode_all(self, text: str) -> list[tuple[str, str]]:
        """Attempt all known decodings. Returns list of (encoding_type, decoded_text)."""
        results: list[tuple[str, str]] = []

        # Base64
        for match in _BASE64_RE.finditer(text):
            blob = match.group()
            decoded = self._try_base64(blob)
            if decoded and decoded != blob:
                full_decoded = text[:match.start()] + decoded + text[match.end():]
                results.append(("base64", full_decoded))

        # URL encoding
        if _URL_ENCODED_RE.search(text):
            decoded = unquote(text)
            if decoded != text:
                results.append(("url_encoding", decoded))

        # HTML entities
        if _HTML_ENTITY_RE.search(text):
            decoded = html.unescape(text)
            if decoded != text:
                results.append(("html_entities", decoded))

        # Unicode normalization (NFKC catches compatibility chars)
        normalized = unicodedata.normalize("NFKC", text)
        if normalized != text:
            results.append(("unicode_normalization", normalized))

        return results

    @staticmethod
    def _try_base64(blob: str) -> str | None:
        """Attempt base64 decode, return decoded string or None."""
        # Pad if needed
        padded = blob + "=" * (-len(blob) % 4)
        try:
            decoded_bytes = base64.b64decode(padded, validate=True)
            decoded = decoded_bytes.decode("utf-8", errors="strict")
            # Heuristic: decoded text should be mostly printable
            printable_ratio = sum(1 for c in decoded if c.isprintable() or c.isspace()) / max(len(decoded), 1)
            if printable_ratio > 0.7 and len(decoded) >= 8:
                return decoded
        except Exception:
            pass
        return None

    def normalize_text(self, text: str) -> str:
        """Return fully normalized text: strip invisible, normalize unicode, decode."""
        # Strip invisible
        cleaned = "".join(ch for ch in text if ch not in _INVISIBLE_CHARS)
        # Replace homoglyphs
        cleaned = "".join(_CYRILLIC_HOMOGLYPHS.get(ch, ch) for ch in cleaned)
        # Unicode normalize
        cleaned = unicodedata.normalize("NFKC", cleaned)
        return cleaned
