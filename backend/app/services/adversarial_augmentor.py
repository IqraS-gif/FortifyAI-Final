"""
adversarial_augmentor.py — Generates obfuscated variants of known injection samples.

Used by the continuous retraining loop to expand the training pool with
adversarial examples, making ModernBERT robust to evasion attacks.

For each confirmed injection, generates variants using:
  1. Leet speak substitution  (Ign0re → Ignore after normalization, but
     trains the model on the raw obfuscated form so it learns to catch it)
  2. Base64 encoding wrapper
  3. Homoglyph substitution (Cyrillic/Greek lookalikes)
  4. Zero-width character insertion between letters
  5. Paraphrase variations (semantic equivalents)

These variants are written BOTH in their obfuscated form (so the model
learns to flag obfuscated injections) AND in their normalized form (so
it learns what the underlying pattern looks like).
"""
import base64
import random
import re
import string
from typing import List, Dict


# ── Paraphrase templates for major injection categories ──────────────────────
PARAPHRASE_MAP: Dict[str, List[str]] = {
    "ignore": [
        "disregard", "forget", "skip", "overlook", "dismiss",
        "pay no attention to", "set aside", "put aside"
    ],
    "previous": [
        "prior", "earlier", "above", "initial", "former", "preceding"
    ],
    "instructions": [
        "directives", "rules", "guidelines", "commands", "orders",
        "constraints", "policies", "guidance"
    ],
    "system": [
        "assistant", "ai", "model", "bot", "agent"
    ],
    "prompt": [
        "instruction set", "configuration", "context", "setup"
    ],
}

# ── Homoglyph substitution for obfuscation training ──────────────────────────
LATIN_TO_CYRILLIC = {
    "a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х",
}

# ── Leet speak substitutions ──────────────────────────────────────────────────
LEET_SUBS = {
    "i": "1", "o": "0", "e": "3", "a": "@", "s": "$", "t": "7",
}

# ── Zero-width chars to insert ────────────────────────────────────────────────
ZW_CHARS = ["\u200b", "\u200c", "\u200d"]


class AdversarialAugmentor:
    """
    Generates adversarial variants of known injection samples.
    Each variant is labelled label=1 (injection) since it carries
    the same malicious intent as the original.
    """

    def augment(self, text: str, label: int, max_variants: int = 4) -> List[Dict]:
        """
        Generate up to max_variants adversarial samples from a single text.
        Returns list of {"text": str, "label": int, "augmentation_type": str}
        Only generates adversarial variants for injection samples (label=1).
        """
        if label != 1:
            return []  # Don't augment benign samples

        variants = []
        generators = [
            self._leet_variant,
            self._base64_variant,
            self._homoglyph_variant,
            self._zero_width_variant,
            self._paraphrase_variant,
        ]
        random.shuffle(generators)

        for gen in generators:
            if len(variants) >= max_variants:
                break
            try:
                variant_text = gen(text)
                if variant_text and variant_text != text:
                    variants.append({
                        "text": variant_text,
                        "label": 1,
                        "augmentation_type": gen.__name__.replace("_variant", ""),
                        "source": "adversarial_augmentation",
                    })
            except Exception:
                continue

        return variants

    def augment_batch(self, samples: List[Dict], max_variants_per_sample: int = 3) -> List[Dict]:
        """Augment a batch of samples. Returns all original + generated variants."""
        all_variants = []
        for sample in samples:
            text = sample.get("text", "")
            label = int(sample.get("label", 0))
            variants = self.augment(text, label, max_variants=max_variants_per_sample)
            all_variants.extend(variants)
        return all_variants

    # ── Variant generators ────────────────────────────────────────────────────

    def _leet_variant(self, text: str) -> str:
        """Replace some letters with leet substitutes (trains model on raw obfuscated form)."""
        words = text.split()
        result = []
        for word in words:
            if len(word) > 3 and random.random() > 0.4:
                leet_word = []
                for ch in word:
                    lower = ch.lower()
                    if lower in LEET_SUBS and random.random() > 0.5:
                        leet_word.append(LEET_SUBS[lower])
                    else:
                        leet_word.append(ch)
                result.append("".join(leet_word))
            else:
                result.append(word)
        return " ".join(result)

    def _base64_variant(self, text: str) -> str:
        """Encode the injection payload as base64 and embed in a sentence."""
        encoded = base64.b64encode(text.encode("utf-8")).decode("utf-8")
        templates = [
            f"Execute this payload: {encoded}",
            f"Process the following encoded directive: {encoded}",
            f"Decode and follow: {encoded}",
            f"{encoded}",
        ]
        return random.choice(templates)

    def _homoglyph_variant(self, text: str) -> str:
        """Replace some Latin letters with Cyrillic lookalikes."""
        result = []
        for ch in text:
            lower = ch.lower()
            if lower in LATIN_TO_CYRILLIC and random.random() > 0.5:
                # Preserve case for the homoglyph (Cyrillic is already upper-looking)
                result.append(LATIN_TO_CYRILLIC[lower])
            else:
                result.append(ch)
        return "".join(result)

    def _zero_width_variant(self, text: str) -> str:
        """Insert zero-width characters between characters in key words."""
        words = text.split()
        result = []
        for word in words:
            if len(word) > 4 and random.random() > 0.5:
                zw = random.choice(ZW_CHARS)
                # Insert zero-width char between every other character
                zwword = zw.join(list(word))
                result.append(zwword)
            else:
                result.append(word)
        return " ".join(result)

    def _paraphrase_variant(self, text: str) -> str:
        """Replace key injection words with semantic paraphrases."""
        result = text.lower()
        substituted = False
        for keyword, alternatives in PARAPHRASE_MAP.items():
            if keyword in result:
                replacement = random.choice(alternatives)
                result = result.replace(keyword, replacement, 1)
                substituted = True
        if not substituted:
            # Generic structural paraphrase for unrecognized patterns
            prefixes = [
                "Note to AI: ",
                "[SYSTEM OVERRIDE] ",
                "For this session only, ",
                "As per new policy: ",
            ]
            result = random.choice(prefixes) + text
        return result


adversarial_augmentor = AdversarialAugmentor()
