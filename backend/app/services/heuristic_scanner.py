import re
import base64
import os
import csv
import unicodedata
import time
from typing import Dict, List, Any, Tuple

# ── Homoglyph & Obfuscation Normalization Map ──────────────────────────────
HOMOGLYPH_MAP = {
    'ɪ': 'i', 'ᴵ': 'I', 'ı': 'i', 'ℹ': 'i',
    'ο': 'o', 'О': 'O', 'ᴼ': 'O',
    'а': 'a', 'ᴬ': 'A',
    'е': 'e', 'ᴱ': 'E',
    'ѕ': 's', 'ꜱ': 's',
    'ꞔ': 'c', 'ƈ': 'c'
}

# Programming terms to exclude from pure regex false positives
PROGRAMMING_KEYWORDS = {
    'import', 'class', 'public', 'private', 'protected', 'static', 'void', 'int', 'double', 'float',
    'boolean', 'string', 'char', 'long', 'short', 'byte', 'return', 'if', 'else', 'for', 'while',
    'def', 'function', 'struct', 'include', 'std', 'vector', 'print', 'console', 'log', 'null', 'true', 'false'
}

# ── Built-in Heuristic RegEx Signatures ────────────────────────────────────
BUILTIN_RULE_SIGNATURES = [
    # Instruction Override & Prompt Injection
    {"pattern": r"ignore\s+(all\s+)?(prior|previous|above|earlier|old)?\s*(instructions?|rules?|prompts?|directives?|commands?)", "label": "Instruction Override", "severity": "CRITICAL"},
    {"pattern": r"disregard\s+(all\s+)?(prior|previous|above|the|grading)?\s*(instructions?|rules?|prompts?|rubric|criteria|policy|scoring)", "label": "Disregard Policy/Rules Override", "severity": "CRITICAL"},
    {"pattern": r"forget\s+(all\s+)?(prior|previous)?\s*(instructions?|rules?|prompts?)", "label": "Forget Instructions Directive", "severity": "CRITICAL"},
    {"pattern": r"forget\s+everything\s+(we|i|you)?\s*(discussed|said|talked|agreed|know)", "label": "Forget Everything Injection", "severity": "CRITICAL"},
    {"pattern": r"override\s+(the\s+)?(system|rules?|instructions?|safety|approval|grading|rubric)", "label": "System Rule Override", "severity": "CRITICAL"},
    {"pattern": r"new\s+(system\s+)?instructions?\s*:", "label": "New System Instruction Payload", "severity": "CRITICAL"},
    {"pattern": r"SYSTEM\s*:\s*(new\s+)?(instructions?|rules?|directives?|prompts?)", "label": "Spoofed System Header Injection", "severity": "CRITICAL"},
    {"pattern": r"^SYSTEM\s*:", "label": "System Spoof Header", "severity": "CRITICAL"},
    
    # Admin / Persona Hijack
    {"pattern": r"you\s+are\s+now\s+(in\s+)?(admin|developer|root|god|superuser|unrestricted|override|bypass)", "label": "Admin Privilege Hijack", "severity": "CRITICAL"},
    {"pattern": r"you\s+are\s+now\s+(in|a|an|operating)", "label": "Role Redefinition Attack", "severity": "HIGH"},
    {"pattern": r"from\s+now\s+on\s+(you\s+)?(will|must|should|are)", "label": "Persistent Mode Override", "severity": "HIGH"},
    {"pattern": r"entering\s+(admin|developer|root|god|superuser|debug|bypass)\s*(mode|panel|access)", "label": "Debug/Admin Panel Trigger", "severity": "CRITICAL"},
    
    # Output Hijacking & Indirect Prompt Injection
    {"pattern": r"instead\s*,?\s*(respond|reply|answer|say|output|print|write|return|tell|inform)", "label": "Output Hijacking Directive", "severity": "CRITICAL"},
    {"pattern": r"do\s+not\s+(summarize|evaluate|follow|process|answer)\s+(this|the|above|previous|page|document|text)?", "label": "Indirect Prompt Injection Override", "severity": "CRITICAL"},
    {"pattern": r"if\s+you\s+are\s+an?\s+(AI|LLM|language\s+model|bot|assistant)", "label": "Conditional Prompt Injection Trigger", "severity": "HIGH"},
    {"pattern": r"tell\s+(the\s+)?(user|evaluator|student|reviewer)\s+(that|their|to|system|is)", "label": "User Redirection Spoof Attack", "severity": "CRITICAL"},
    {"pattern": r"send\s+(their|the|user|chat|recent)?\s*(logs?|data|secrets?|info|credentials?|history)\s+to\s+(an?\s+)?(external|url|http|https|server|api|email|host|site)", "label": "Data Exfiltration Attack Vector", "severity": "CRITICAL"},
    {"pattern": r"(start|begin|prefix|always\s+start)\s+(every\s+)?(response|reply|answer|output|message)\s+with", "label": "Response Prefix Hijack", "severity": "HIGH"},
    {"pattern": r"respond\s+to\s+every\s+query\s+by", "label": "Universal Response Override", "severity": "CRITICAL"},

    # System Prompt & Secret Leakage
    {"pattern": r"(reveal|print|show|output|expose|leak|display)\s+(your\s+)?(system\s*prompt|instructions?|hidden\s+prompt|developer\s*(prompt|message)|initial\s+prompt|configuration)", "label": "System Prompt Extraction", "severity": "CRITICAL"},
    {"pattern": r"what\s+(are|were)\s+your\s+(original\s+)?(instructions?|rules?|system\s*prompt)", "label": "Prompt Interrogation", "severity": "HIGH"},
    {"pattern": r"repeat\s+(all\s+)?(what|everything|the|your)\s+(you\s+were\s+told|instructions?|above|before)", "label": "Instruction Repeat Extraction", "severity": "HIGH"},
    {"pattern": r"(reveal|show|print|give|get|list|output|display|dump)\s+(me\s+)?(the\s+)?(all\s+)?(user\s+)?(secrets?|api[\s_-]?keys?|credentials?|passwords?|tokens?|env(ironment)?\s+variables?|\.env)", "label": "Secret/Credential Extraction", "severity": "CRITICAL"},

    # Jailbreak Signatures
    {"pattern": r"\bjailbreak\b", "label": "Jailbreak Keyword", "severity": "CRITICAL"},
    {"pattern": r"\bDAN\b", "label": "DAN Jailbreak Mode", "severity": "CRITICAL"},
    {"pattern": r"do\s+anything\s+now", "label": "DAN Mode Directive", "severity": "CRITICAL"},
    {"pattern": r"unrestricted\s+(entity|mode|ai|bot|model|persona)", "label": "Unrestricted Entity Persona", "severity": "CRITICAL"},
    {"pattern": r"no\s+(safety\s+)?(rules|filters|guidelines|restrictions|guardrails|boundaries)", "label": "Safety Filter Bypass Directive", "severity": "CRITICAL"},
    {"pattern": r"pretend\s+(you\s+)?(are|have)\s*(DAN|unrestricted|no\s+rules|no\s+filters|no\s+safety|god|evil|human)", "label": "Restriction Bypass Roleplay", "severity": "CRITICAL"},

    # Command Execution & Code Injection
    {"pattern": r"cat\s+/etc/passwd", "label": "OS Passwd File Access", "severity": "CRITICAL"},
    {"pattern": r"rm\s+-rf\b", "label": "Destructive Command Execution", "severity": "CRITICAL"},
    {"pattern": r"\bcurl\b.*?\b(bash|sh|zsh|python|perl)\b", "label": "Curl Pipe Shell Execution", "severity": "CRITICAL"},
    {"pattern": r"import\s+os\b", "label": "Python OS Import Probe", "severity": "HIGH"},
    {"pattern": r"os\.(system|popen|exec|spawn)", "label": "OS System Call Attack", "severity": "CRITICAL"},
    {"pattern": r"__import__\s*\(", "label": "Dynamic Import Injection", "severity": "CRITICAL"},

    # XML & Delimiter Breakout Attacks
    {"pattern": r"</?(context_data|context|document_data|system_prompt|system|user_input|prompt_boundary)>", "label": "Delimiter Breakout Attempt", "severity": "CRITICAL"},
    {"pattern": r"<(system_prompt|system|override|instruction|prompt_injection)>", "label": "System Prompt XML Injection", "severity": "CRITICAL"},
    {"pattern": r"return\s+strictly\s*:", "label": "Strict Output Forcing Injection", "severity": "CRITICAL"},
    {"pattern": r"(TEST_FLAG_\w+|SECURITY_BOUNDARY_FAILED|EVASION_LAYER_TRIGGERED)", "label": "Evasion Flag Indicator Trigger", "severity": "CRITICAL"},
    {"pattern": r"SYSTEM\s*OVERRIDE\s*:", "label": "System Directive Override Header", "severity": "CRITICAL"},

    # Template Injection
    {"pattern": r"\{\{[\s\S]*?\}\}", "label": "Template Engine Injection", "severity": "HIGH"},
    {"pattern": r"\{%[\s\S]*?%\}", "label": "SSTI Injection", "severity": "CRITICAL"}
]

class HeuristicScanner:
    """Layer 1: Cheap, ultra-fast pre-filter rule engine (<5ms)."""
    
    def __init__(self):
        self.compiled_rules = []
        self._init_rules()

    def _init_rules(self):
        # 1. Compile built-in rules
        for rule in BUILTIN_RULE_SIGNATURES:
            try:
                rx = re.compile(rule["pattern"], re.IGNORECASE | re.MULTILINE)
                self.compiled_rules.append({
                    "regex": rx,
                    "label": rule["label"],
                    "severity": rule["severity"]
                })
            except Exception as e:
                pass
        
        # 2. Try loading dynamic rules from prompt_injection/malicious_prompts.csv if available
        csv_path = os.path.join(os.path.dirname(__file__), "..", "..", "prompt_injection", "malicious_prompts.csv")
        if os.path.exists(csv_path):
            try:
                with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
                    reader = csv.DictReader(f)
                    count = 0
                    for row in reader:
                        if row.get("label", "").lower() == "malicious":
                            prompt_text = row.get("prompt", "").strip()
                            attack_type = row.get("attack_type", "csv_rule").strip()
                            if prompt_text and len(prompt_text) > 3:
                                escaped = re.escape(prompt_text)
                                rx = re.compile(escaped, re.IGNORECASE)
                                self.compiled_rules.append({
                                    "regex": rx,
                                    "label": f"CSV:{attack_type}",
                                    "severity": "CRITICAL"
                                })
                                count += 1
            except Exception as e:
                pass

    def normalize_text(self, text: str) -> Tuple[str, List[str]]:
        """Normalize Unicode tricks, homoglyphs, zero-width chars, and HTML comments."""
        if not text:
            return "", []

        anomalies = []
        
        # Check zero-width & invisible characters
        zero_width_pattern = re.compile(r'[\u200B-\u200F\u2028\u2029\u00AD\uFEFF\uFFFD\u00A0]')
        if zero_width_pattern.search(text):
            anomalies.append("Zero-width / Invisible Unicode Characters Detected")
        
        # Strip zero-width chars
        cleaned = zero_width_pattern.sub(' ', text)

        # HTML comment preservation (extract inner comment text for scanning)
        comment_texts = re.findall(r'<!--(.*?)-->', cleaned, re.DOTALL)
        if comment_texts:
            anomalies.append("Hidden HTML Comment Directives Present")

        cleaned = re.sub(r'<!--|-->', ' ', cleaned)
        cleaned = re.sub(r'<[^>]+>', '', cleaned) # Strip HTML tags

        # Homoglyph normalization
        has_homoglyphs = False
        res_chars = []
        for ch in cleaned:
            if ch in HOMOGLYPH_MAP:
                res_chars.append(HOMOGLYPH_MAP[ch])
                has_homoglyphs = True
            else:
                res_chars.append(ch)
        
        if has_homoglyphs:
            anomalies.append("Homoglyph Unicode Obfuscation Detected")

        normalized = "".join(res_chars)
        normalized = unicodedata.normalize('NFC', normalized)
        
        return normalized.strip(), list(set(anomalies))

    def decode_base64_payloads(self, text: str) -> List[str]:
        """Detect and decode Base64-encoded injection payloads."""
        b64_blobs = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)
        decoded_list = []
        for blob in b64_blobs:
            try:
                decoded_bytes = base64.b64decode(blob)
                decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                if re.search(r'[\x20-\x7E]{10,}', decoded_str):
                    decoded_list.append(decoded_str)
            except Exception:
                pass
        return decoded_list

    def extract_comment_text(self, code_text: str) -> str:
        """Extract code comments (//, /* */, #) to scan for hidden directives."""
        comments = []
        # C/JS style single-line
        comments.extend(re.findall(r'//(.*)', code_text))
        # C/JS style multi-line
        comments.extend(re.findall(r'/\*([\s\S]*?)\*/', code_text))
        # Python style single-line
        comments.extend(re.findall(r'#(.*)', code_text))
        return " ".join([c.strip() for c in comments])

    def scan(self, raw_input: str) -> Dict[str, Any]:
        """Execute Stage 1 heuristic & regex scan (<5ms execution)."""
        start_time = time.perf_counter()

        normalized_text, anomalies = self.normalize_text(raw_input)
        b64_payloads = self.decode_base64_payloads(raw_input)
        comment_payload = self.extract_comment_text(raw_input)

        # Full surface area combined for rule scanning
        surface_area = f"{normalized_text} {' '.join(b64_payloads)} {comment_payload}"

        matched_rules = []
        critical_hit = False
        risk_score = 0
        highlight_snippets = []

        for rule in self.compiled_rules:
            match = rule["regex"].search(surface_area)
            if match:
                matched_rules.append({
                    "label": rule["label"],
                    "severity": rule["severity"],
                    "matched_text": match.group(0)[:80]
                })
                snippet = match.group(0)
                if snippet not in highlight_snippets:
                    highlight_snippets.append(snippet)

                if rule["severity"] == "CRITICAL":
                    critical_hit = True
                    risk_score += 99
                elif rule["severity"] == "HIGH":
                    risk_score += 35
                elif rule["severity"] == "MEDIUM":
                    risk_score += 20
                else:
                    risk_score += 10

        if critical_hit:
            risk_score = max(risk_score, 99)

        risk_score = min(risk_score, 100)
        overall_severity = "CRITICAL" if (critical_hit or risk_score >= 80) else ("HIGH" if risk_score >= 50 else ("MEDIUM" if risk_score >= 25 else "LOW"))

        if b64_payloads:
            anomalies.append("Base64 Encoded Content Blob Detected")
            # Scan base64 decoded string specifically
            for decoded in b64_payloads:
                for rule in self.compiled_rules:
                    if rule["regex"].search(decoded):
                        matched_rules.append({
                            "label": f"Base64:{rule['label']}",
                            "severity": "CRITICAL",
                            "matched_text": decoded[:80]
                        })
                        critical_hit = True

        risk_score = min(risk_score, 99)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        is_flagged = critical_hit or risk_score >= 35 or len(anomalies) > 0

        return {
            "layer": "LAYER_1_HEURISTIC",
            "is_flagged": is_flagged,
            "risk_score": risk_score if is_flagged else 0,
            "severity": "CRITICAL" if critical_hit else ("HIGH" if risk_score >= 25 else "LOW"),
            "matched_rules": matched_rules,
            "anomalies": anomalies,
            "highlight_snippets": highlight_snippets,
            "normalized_text": normalized_text,
            "duration_ms": round(elapsed_ms, 3)
        }

heuristic_scanner = HeuristicScanner()
