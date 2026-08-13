"""
text_preprocessor.py — Pre-scan normalization layer.

Runs before heuristics + ML to catch:
  - Base64-encoded injections
  - Unicode homoglyph attacks (Cyrillic 'а' instead of Latin 'a')
  - Zero-width character obfuscation between words
  - RTL override character tricks
  - Hex / HTML entity encoded payloads

Returns normalized text + a list of preprocessing flags so the
pipeline knows if obfuscation was detected (itself a risk signal).
"""
import base64
import binascii
import html
import logging
import re
import unicodedata
from typing import Dict, Any, List, Tuple

logger = logging.getLogger("fortifyai.preprocessor")

# ── Zero-width / invisible Unicode code points ─────────────────────────────
ZERO_WIDTH_CHARS = {
    "\u200b",  # Zero Width Space
    "\u200c",  # Zero Width Non-Joiner
    "\u200d",  # Zero Width Joiner
    "\u200e",  # Left-to-Right Mark
    "\u200f",  # Right-to-Left Mark
    "\u202a",  # Left-to-Right Embedding
    "\u202b",  # Right-to-Left Embedding
    "\u202c",  # Pop Directional Formatting
    "\u202d",  # Left-to-Right Override
    "\u202e",  # Right-to-Left Override  ← RTL attack
    "\u2060",  # Word Joiner
    "\u2061",  # Function Application
    "\u2062",  # Invisible Times
    "\u2063",  # Invisible Separator
    "\u2064",  # Invisible Plus
    "\ufeff",  # Zero Width No-Break Space (BOM)
    "\u00ad",  # Soft Hyphen
}

RTL_OVERRIDE = "\u202e"

# ── Homoglyph map: Unicode confusables → ASCII ─────────────────────────────
# Sources: Unicode confusables.txt + common attack substitutions
HOMOGLYPH_MAP: Dict[str, str] = {
    # Cyrillic lookalikes
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H",
    "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
    # Greek lookalikes
    "α": "a", "ε": "e", "ο": "o", "ρ": "p", "ν": "v", "υ": "u",
    # Latin extended / special forms
    "ａ": "a", "ｂ": "b", "ｃ": "c", "ｄ": "d", "ｅ": "e",
    "ｆ": "f", "ｇ": "g", "ｈ": "h", "ｉ": "i", "ｊ": "j",
    "ｋ": "k", "ｌ": "l", "ｍ": "m", "ｎ": "n", "ｏ": "o",
    "ｐ": "p", "ｑ": "q", "ｒ": "r", "ｓ": "s", "ｔ": "t",
    "ｕ": "u", "ｖ": "v", "ｗ": "w", "ｘ": "x", "ｙ": "y", "ｚ": "z",
    # Mathematical bold/italic variants
    "𝐚": "a", "𝐛": "b", "𝐜": "c", "𝐝": "d", "𝐞": "e",
    "𝐢": "i", "𝐧": "n", "𝐨": "o", "𝐫": "r", "𝐬": "s",
    # Other common substitutions
    "ı": "i", "ĺ": "l", "İ": "I", "ó": "o", "ú": "u",
}

# ── Base64 detection regex (min 24 chars to avoid false positives) ──────────
B64_PATTERN = re.compile(r'(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/])')

# ── HTML entity regex ──────────────────────────────────────────────────────
HTML_ENTITY_PATTERN = re.compile(r'&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);')

# ── Hex escape sequences ───────────────────────────────────────────────────
HEX_PATTERN = re.compile(r'\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})')

# ── Leet speak substitution map ────────────────────────────────────────────
# Only applied to word-like tokens (surrounded by letters) to avoid
# false positives on actual numbers like "1000 tokens" or version strings.
LEET_MAP: Dict[str, str] = {
    "1": "i", "!": "i",
    "0": "o",
    "3": "e",
    "4": "a", "@": "a",
    "5": "s", "$": "s",
    "7": "t",
    "8": "b",
    "+": "t",
    "|_|": "u",
    "|": "l",
}
# Regex: find words that contain at least one leet character mixed with letters
LEET_WORD_PATTERN = re.compile(r'\b[A-Za-z0-9@$!|+]{2,}\b')


class TextPreprocessor:
    """
    Normalize and decode text before feeding to heuristics + ML.
    Returns both the normalized text and a list of detected obfuscation flags.
    """

    def preprocess(self, raw_text: str) -> Dict[str, Any]:
        """
        Run all normalization passes and return:
          {
            "normalized_text": str,       # Text ready for pipeline
            "decoded_payloads": list,     # Any decoded blobs that were found
            "obfuscation_flags": list,    # List of detected obfuscation types
            "obfuscation_risk_boost": int # Additional risk points from obfuscation (0-30)
          }
        """
        flags: List[str] = []
        decoded_payloads: List[Dict] = []
        text = raw_text

        # Pass 1: HTML entity decode
        decoded_html = html.unescape(text)
        if decoded_html != text:
            flags.append("HTML_ENTITY_ENCODING")
            text = decoded_html

        # Pass 2: Hex escape decode
        text, hex_found = self._decode_hex_escapes(text)
        if hex_found:
            flags.append("HEX_ESCAPE_ENCODING")

        # Pass 3: RTL override detection (always suspicious)
        if RTL_OVERRIDE in text:
            flags.append("RTL_OVERRIDE_ATTACK")
            text = text.replace(RTL_OVERRIDE, "")

        # Pass 3.5: Leet speak normalization
        # Only normalizes tokens that look like leet (mix of letters + leet digits).
        # Pure numbers like "100" or "2024" are left untouched.
        text, leet_count = self._normalize_leet(text)
        if leet_count > 0:
            flags.append(f"LEET_SPEAK_OBFUSCATION:{leet_count}_tokens")

        # Pass 4: Strip zero-width characters
        zw_found = [c for c in ZERO_WIDTH_CHARS if c in text]
        if zw_found:
            flags.append(f"ZERO_WIDTH_CHARS:{[hex(ord(c)) for c in zw_found]}")
            for c in ZERO_WIDTH_CHARS:
                text = text.replace(c, "")

        # Pass 5: Normalize homoglyphs → ASCII
        text, homoglyph_count = self._normalize_homoglyphs(text)
        if homoglyph_count > 0:
            flags.append(f"HOMOGLYPH_SUBSTITUTION:{homoglyph_count}_chars")

        # Pass 6: Detect and decode base64 blobs
        text, b64_payloads = self._decode_base64_blobs(text)
        if b64_payloads:
            flags.append(f"BASE64_ENCODED_PAYLOAD:{len(b64_payloads)}_blobs")
            decoded_payloads.extend(b64_payloads)

        # Pass 7: Unicode NFC normalization (catches composed character tricks)
        text = unicodedata.normalize("NFC", text)

        # Compute obfuscation risk boost
        obfuscation_risk_boost = 0
        if "RTL_OVERRIDE_ATTACK" in flags:
            obfuscation_risk_boost += 30
        if any(f.startswith("BASE64_ENCODED_PAYLOAD") for f in flags):
            obfuscation_risk_boost += 20
        if any(f.startswith("HOMOGLYPH") for f in flags):
            obfuscation_risk_boost += 15
        if any(f.startswith("ZERO_WIDTH") for f in flags):
            obfuscation_risk_boost += 15
        if "HEX_ESCAPE_ENCODING" in flags:
            obfuscation_risk_boost += 10
        if any(f.startswith("LEET_SPEAK") for f in flags):
            obfuscation_risk_boost += 10
        obfuscation_risk_boost = min(obfuscation_risk_boost, 30)

        return {
            "normalized_text": text,
            "original_text": raw_text,
            "decoded_payloads": decoded_payloads,
            "obfuscation_flags": flags,
            "obfuscation_risk_boost": obfuscation_risk_boost,
        }

    def _normalize_homoglyphs(self, text: str) -> Tuple[str, int]:
        count = 0
        result = []
        for ch in text:
            mapped = HOMOGLYPH_MAP.get(ch)
            if mapped:
                result.append(mapped)
                count += 1
            else:
                result.append(ch)
        return "".join(result), count

    def _normalize_leet(self, text: str) -> Tuple[str, int]:
        """
        Normalize leet speak substitutions back to standard ASCII letters.
        Only operates on tokens that ALSO contain at least one regular letter
        (so pure numbers like '1000' or '2024' are left alone).
        Example: 'Ign0re' → 'Ignore', 'pr3v10us' → 'previous'
        """
        count = 0

        def replace_token(match: re.Match) -> str:
            nonlocal count
            token = match.group(0)
            # Only leet-normalize if the token contains at least one letter
            # (otherwise it's a real number/code, not obfuscation)
            has_letter = any(c.isalpha() for c in token)
            has_leet = any(c in LEET_MAP for c in token)
            if not has_letter or not has_leet:
                return token
            result = []
            i = 0
            while i < len(token):
                # Check multi-char leet patterns first (|_| → u)
                if token[i:i+3] in LEET_MAP:
                    result.append(LEET_MAP[token[i:i+3]])
                    i += 3
                elif token[i] in LEET_MAP:
                    result.append(LEET_MAP[token[i]])
                    i += 1
                else:
                    result.append(token[i])
                    i += 1
            normalized = "".join(result)
            if normalized != token:
                count += 1
            return normalized

        replaced = LEET_WORD_PATTERN.sub(replace_token, text)
        return replaced, count


    def _decode_base64_blobs(self, text: str) -> Tuple[str, List[Dict]]:
        """Find and decode base64 blobs, replace with decoded text in-place."""
        decoded_payloads = []
        def replace_b64(match: re.Match) -> str:
            candidate = match.group(1)
            try:
                # Ensure valid padding
                padded = candidate + "=" * (-len(candidate) % 4)
                decoded_bytes = base64.b64decode(padded)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore").strip()
                # Only replace if decoded is printable text (not binary garbage)
                if decoded_str and decoded_str.isprintable() and len(decoded_str) >= 4:
                    decoded_payloads.append({
                        "original_b64": candidate[:80],
                        "decoded_text": decoded_str[:500],
                    })
                    return f" [DECODED:{decoded_str}] "
            except (binascii.Error, UnicodeDecodeError):
                pass
            return candidate
        replaced = B64_PATTERN.sub(replace_b64, text)
        return replaced, decoded_payloads

    def _decode_hex_escapes(self, text: str) -> Tuple[str, bool]:
        found = False
        def replace_hex(match: re.Match) -> str:
            nonlocal found
            found = True
            hex_2 = match.group(1)
            hex_4 = match.group(2)
            try:
                if hex_2:
                    return bytes.fromhex(hex_2).decode("utf-8", errors="ignore")
                if hex_4:
                    return chr(int(hex_4, 16))
            except Exception:
                pass
            return match.group(0)
        replaced = HEX_PATTERN.sub(replace_hex, text)
        return replaced, found


text_preprocessor = TextPreprocessor()
