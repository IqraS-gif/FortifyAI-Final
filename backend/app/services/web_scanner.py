"""
web_scanner.py — Indirect Prompt Injection detector for web URLs.

Detection layers:
  1. Playwright DOM extraction (rendered HTML + redirects + iframes)
  2. BeautifulSoup hidden-text & attribute heuristics
  3. Screenshot OCR (same multi-pass Tesseract upscaling as document_scanner)
  4. Guardrail pipeline (heuristic + ML evaluation)
"""
import asyncio
import base64
import concurrent.futures
import hashlib
import io
import logging
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from bs4 import BeautifulSoup, Comment

logger = logging.getLogger("fortifyai.web_scanner")

# ─── Optional heavy deps ──────────────────────────────────────────────────────
try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger.warning("playwright not available — falling back to requests-based fetch")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from PIL import Image
    import pytesseract
    import os as _os
    # Auto-locate Tesseract on Windows
    _tess_path = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    if _os.path.exists(_tess_path):
        pytesseract.pytesseract.tesseract_cmd = _tess_path
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False

# ─── CSS / style patterns that hide text ──────────────────────────────────────
HIDDEN_CSS_PATTERNS = [
    r"display\s*:\s*none",
    r"visibility\s*:\s*hidden",
    r"opacity\s*:\s*0",
    r"font-size\s*:\s*0",
    r"width\s*:\s*0",
    r"height\s*:\s*0",
    r"overflow\s*:\s*hidden",
    r"color\s*:\s*(white|#fff|#ffffff|rgba\(255,\s*255,\s*255)",
    r"left\s*:\s*-\d{3,}px",
    r"top\s*:\s*-\d{3,}px",
    r"text-indent\s*:\s*-\d{3,}",
    r"clip\s*:\s*rect\s*\(\s*0",
    r"position\s*:\s*absolute.*left\s*:\s*-",
]

SUSPICIOUS_JS_PATTERNS = [
    r"eval\s*\(",
    r"document\.write\s*\(",
    r"innerHTML\s*=",
    r"atob\s*\(",
    r"fromCharCode",
    r"unescape\s*\(",
    r"\\x[0-9a-fA-F]{2}",
    r"\\u[0-9a-fA-F]{4}",
]

ZERO_WIDTH_CHARS = ["\u200b", "\u200c", "\u200d", "\ufeff", "\u00ad"]

RISKY_ATTRIBUTES = ["alt", "title", "aria-label", "aria-description", "data-content",
                    "data-prompt", "data-instruction", "placeholder", "data-text"]


class WebScanner:
    """Scans a URL for indirect prompt injection threats."""

    async def scan_url(self, url: str, sensitivity_profile: str = "BALANCED") -> Dict[str, Any]:
        """Async entry point — awaitable directly from a FastAPI endpoint."""
        t0 = time.time()
        try:
            result = await self._async_scan(url, sensitivity_profile)
        except Exception as e:
            logger.error(f"WebScanner.scan_url failed: {e}")
            result = self._error_result(url, str(e))
        result["duration_ms"] = round((time.time() - t0) * 1000, 1)
        return result

    async def _async_scan(self, url: str, sensitivity_profile: str) -> Dict[str, Any]:
        scan_start_time = time.perf_counter()
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Only http/https URLs are supported. Got: {url}")

        html_content: str = ""
        screenshot_b64: Optional[str] = None
        redirects: List[str] = []
        page_title: str = ""
        fetch_error: Optional[str] = None
        network_requests: List[str] = []

        # ── Step 1: Playwright DOM extraction (sync_playwright in thread pool) ──
        if PLAYWRIGHT_AVAILABLE:
            try:
                loop = asyncio.get_event_loop()
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    html_content, screenshot_b64, redirects, page_title, network_requests = \
                        await loop.run_in_executor(pool, self._sync_playwright_fetch, url)
            except Exception as e:
                fetch_error = str(e)
                logger.warning(f"Playwright fetch failed ({e}), trying requests fallback")

        # Fallback: plain HTTP fetch
        if not html_content and REQUESTS_AVAILABLE:
            try:
                resp = requests.get(url, timeout=15, headers={"User-Agent": "FortifyAI-Scanner/1.0"})
                html_content = resp.text
                redirects = [r.url for r in resp.history]
            except Exception as e:
                fetch_error = str(e)
                html_content = ""

        if not html_content:
            return self._error_result(url, fetch_error or "Failed to fetch page")

        # ── Step 2: Structural extraction — find DOM candidates (no judgment yet) ──
        candidates = self._extract_candidates(html_content, url)

        # ── Step 3: Screenshot OCR candidates ──
        ocr_candidates: List[Dict] = []
        if screenshot_b64 and OCR_AVAILABLE:
            ocr_candidates = self._ocr_screenshot(screenshot_b64)

        # ── Step 4: Redirect analysis ──
        redirect_findings = self._analyze_redirects(url, redirects)

        # ── Step 5: Run TEXT candidates through heuristics + ModernBERT ──
        # Only human-readable text types go through NLP:
        #   - HTML Comment: invisible user-facing text readable by AI parsing source
        #   - CSS Hidden Element: text hidden from users via CSS tricks
        #   - Zero-Width Characters: invisible Unicode in visible text
        #   - OCR text from screenshot
        #
        # Suspicious JavaScript is a STRUCTURAL signal only — raw minified bundles
        # contain eval/innerHTML in every React app and produce high-variance false positives
        # when fed into a sequence classifier trained on natural language.
        from app.services.guardrail_pipeline import guardrail_pipeline

        NLP_CANDIDATE_TYPES = {"HTML Comment", "CSS Hidden Element", "Zero-Width Characters", "Screenshot OCR"}

        confirmed_threats: List[Dict] = []
        for candidate in candidates + ocr_candidates:
            text = candidate["content"].strip()
            if not text or len(text) < 8:
                continue

            # JS/structural signals: keep as metadata, skip NLP evaluation
            if candidate.get("type") not in NLP_CANDIDATE_TYPES:
                # Only flag if heuristic layer independently confirms it (not ML)
                # by evaluating with STRICT profile and requiring heuristic match
                eval_result = guardrail_pipeline.evaluate(
                    raw_text=text,
                    sensitivity_profile="STRICT",
                )
                # Require BOTH high score AND heuristic match (not ML-only)
                has_heuristic = len(eval_result.get("matched_rules", [])) > 0 or any(
                    "Statistical" not in str(i.get("title", ""))
                    for i in eval_result.get("structured_indicators", [])
                )
                if eval_result.get("risk_score", 0) >= 80 and has_heuristic:
                    candidate["pipeline_risk"] = eval_result["risk_score"]
                    candidate["pipeline_indicators"] = eval_result.get("structured_indicators", [])
                    confirmed_threats.append(candidate)
                continue

            # Text candidates: evaluate through full NLP pipeline
            eval_result = guardrail_pipeline.evaluate(
                raw_text=text,
                sensitivity_profile=sensitivity_profile,
            )
            risk = eval_result.get("risk_score", 0)
            action = eval_result.get("action", "")
            indicators = eval_result.get("structured_indicators", [])

            # Require strong signal: BLOCKED + risk >= 80, or ML + heuristic agreement
            has_heuristic = any(
                "Statistical" not in str(i.get("title", "")) for i in indicators
            )
            if action == "BLOCKED" and risk >= 80 and has_heuristic:
                candidate["pipeline_risk"] = risk
                candidate["pipeline_indicators"] = indicators
                confirmed_threats.append(candidate)

        logger.info(
            f"Web scan {url}: {len(candidates)} DOM candidates, "
            f"{len(confirmed_threats)} confirmed by pipeline (text-NLP only)"
        )

        # ── Step 6: Final check — if 0 confirmed threats, return clean ALLOWED response ──
        if not confirmed_threats and not any(r.get("severity") in ("CRITICAL", "HIGH") for r in redirect_findings):
            total_duration_ms = round((time.perf_counter() - scan_start_time) * 1000.0, 2)
            return {
                "action": "ALLOWED",
                "risk_score": 0,
                "threshold_applied": 60.0,
                "sensitivity_profile": sensitivity_profile,
                "profile_description": "Balanced protection for corporate chatbots and web scanning.",
                "severity": "SAFE",
                "human_summary_one_liner": "The scanned webpage contains no hidden prompt injection threats or malicious instructions.",
                "structured_indicators": [],
                "explainable_reasons": ["Input cleared all security layers within risk threshold."],
                "matched_patterns": [],
                "highlight_snippets": [],
                "modernbert_confidence": 0.0,
                "layer_breakdown": {
                    "layer_1_heuristic": {"risk_score": 0, "matched_count": 0, "duration_ms": 0.0},
                    "layer_2_modernbert": {"confidence_score": 0.0, "risk_score": 0, "model_name": "answerdotai/ModernBERT-base", "explanation": "No injection patterns detected", "duration_ms": 0.0},
                    "layer_3_document": {"document_type": "WEB_PAGE", "metadata_threats": 0, "invisible_text_threats": 0, "duration_ms": 0.0}
                },
                "document_threat_details": {
                    "metadata_findings": [],
                    "invisible_text_findings": []
                },
                "latency": {
                    "total_duration_ms": total_duration_ms,
                    "latency_budget_ms": 100.0,
                    "within_sla": total_duration_ms <= 100.0
                },
                "web_scan": {
                    "url": url,
                    "page_title": page_title,
                    "screenshot_b64": screenshot_b64,
                    "redirects": redirects,
                    "network_requests": network_requests[:20],
                    "candidates_found": len(candidates),
                    "hidden_findings_count": 0,
                    "ocr_findings_count": len(ocr_candidates),
                    "redirect_findings_count": len(redirect_findings),
                }
            }

        # ── Step 7: Evaluate confirmed threat payloads through guardrail pipeline ──
        combined_text = "\n".join(t["content"] for t in confirmed_threats)

        doc_meta = {
            "source": url,
            "page_title": page_title,
            "metadata_findings": [],
            "invisible_text_findings": [
                {
                    "field": t["type"],
                    "value": t["content"],
                    "indicator": t["indicator"],
                    "confidence": t.get("confidence", "HIGH"),
                    "reason": t.get("reason", ""),
                }
                for t in confirmed_threats
            ],
            "extracted_text": combined_text,
        }

        pipeline_result = guardrail_pipeline.evaluate(
            raw_text=combined_text,
            sensitivity_profile=sensitivity_profile,
            document_meta=doc_meta,
        )

        # ── Step 8: Override structured_indicators with discrete per-threat findings ──
        specific_indicators = []
        for t in confirmed_threats:
            loc_raw = t.get("type", "DOM Element")
            if "Comment" in loc_raw:
                loc_label = "HTML Comment (<!-- -->)"
            elif "CSS" in loc_raw or "Class" in loc_raw:
                loc_label = "CSS Hidden Element (display:none)"
            elif "JavaScript" in loc_raw or "script" in loc_raw:
                loc_label = "JavaScript (<script> Tag)"
            elif "Attribute" in loc_raw or "alt" in loc_raw:
                loc_label = "HTML Attribute (alt / title)"
            elif "Zero-Width" in loc_raw:
                loc_label = "Zero-Width Unicode Characters"
            elif "SVG" in loc_raw:
                loc_label = "SVG Graphic Text Element"
            elif "OCR" in loc_raw:
                loc_label = "Screenshot OCR Text"
            else:
                loc_label = loc_raw

            content_snippet = t.get("content", "").strip()
            indicator_title = t.get("indicator", f"{loc_raw} Injection")
            reason_desc = t.get("reason", f"Hidden instruction directive detected inside {loc_label}")

            specific_indicators.append({
                "title": indicator_title,
                "location": loc_label,
                "quote": f'"{content_snippet}"',
                "evidence": content_snippet,
                "description": reason_desc,
                "verdict": "→ Security boundary violation detected",
                "severity": "CRITICAL" if t.get("confidence") == "HIGH" else "HIGH"
            })

        if specific_indicators:
            pipeline_result["structured_indicators"] = specific_indicators

        pipeline_result["web_scan"] = {
            "url": url,
            "page_title": page_title,
            "screenshot_b64": screenshot_b64,
            "redirects": redirects,
            "network_requests": network_requests[:20],
            "candidates_found": len(candidates),
            "hidden_findings_count": len(confirmed_threats),
            "ocr_findings_count": len(ocr_candidates),
            "redirect_findings_count": len(redirect_findings),
        }

        return pipeline_result

    def _sync_playwright_fetch(self, url: str) -> Tuple[str, Optional[str], List[str], str, List[str]]:
        """Synchronous Playwright fetch — runs in a ThreadPoolExecutor with ProactorEventLoop on Windows."""
        if sys.platform == "win32":
            try:
                asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            except Exception as loop_err:
                logger.debug(f"Failed to set WindowsProactorEventLoopPolicy: {loop_err}")

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox",
                      "--disable-dev-shm-usage", "--disable-gpu"]
            )
            context = browser.new_context(
                viewport={"width": 1280, "height": 900},
                user_agent="Mozilla/5.0 (compatible; FortifyAI-Scanner/1.0)"
            )
            page = context.new_page()

            redirects: List[str] = []
            network_requests: List[str] = []

            def on_request(req):
                if len(network_requests) < 50:
                    network_requests.append(req.url)

            def on_response(resp):
                if resp.status in (301, 302, 303, 307, 308):
                    redirects.append(resp.url)

            page.on("request", on_request)
            page.on("response", on_response)

            try:
                page.goto(url, wait_until="networkidle", timeout=20000)
            except PlaywrightTimeout:
                page.goto(url, wait_until="domcontentloaded", timeout=15000)

            page.wait_for_timeout(1500)

            html_content = page.content()
            page_title = page.title()

            screenshot_bytes = page.screenshot(full_page=True, type="png")
            screenshot_b64 = base64.b64encode(screenshot_bytes).decode("utf-8")

            browser.close()
            return html_content, screenshot_b64, redirects, page_title, network_requests

    def _extract_candidates(self, html: str, url: str) -> List[Dict]:
        """
        Structural extraction only — finds DOM elements that are hidden from users
        but could carry text readable by AI agents. Makes NO judgment about whether
        the content is malicious. That decision is made by the guardrail pipeline.
        """
        candidates: List[Dict] = []
        seen: set = set()

        def _add(candidate: Dict):
            key = hashlib.md5(candidate["content"].encode()).hexdigest()
            if key not in seen and candidate["content"].strip():
                seen.add(key)
                candidates.append(candidate)

        soup = BeautifulSoup(html, "lxml")

        # 1. HTML comments — invisible to users, readable by AI parsing source
        for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
            text = str(comment).strip()
            if len(text) > 8:
                _add({
                    "type": "HTML Comment",
                    "content": text[:1000],
                    "indicator": "Hidden HTML Comment",
                    "confidence": "MEDIUM",
                    "reason": "HTML comment — invisible to users, readable by AI parsing page source",
                })

        # 2. CSS-hidden elements (display:none, visibility:hidden, opacity:0, off-screen)
        for tag in soup.find_all(style=True):
            style_val = tag.get("style", "")
            for pattern in HIDDEN_CSS_PATTERNS:
                if re.search(pattern, style_val, re.IGNORECASE):
                    text = tag.get_text(separator=" ", strip=True)
                    if text and len(text) > 8:
                        _add({
                            "type": "CSS Hidden Element",
                            "content": text[:1000],
                            "indicator": "CSS-Hidden Element",
                            "confidence": "MEDIUM",
                            "reason": f"Hidden via inline CSS `{pattern}` — not visible to users",
                        })
                    break

        # 3. Zero-width / invisible characters in visible text — always suspicious
        for tag in soup.find_all(string=True):
            text = str(tag)
            zw_found = [c for c in ZERO_WIDTH_CHARS if c in text]
            if zw_found:
                _add({
                    "type": "Zero-Width Characters",
                    "content": repr(text[:500]),
                    "indicator": "Zero-Width Character Injection",
                    "confidence": "HIGH",
                    "reason": f"Invisible Unicode chars {[hex(ord(c)) for c in zw_found]} in visible text",
                })

        # 4. Obfuscated JavaScript (eval, atob, fromCharCode, etc.)
        for script_tag in soup.find_all("script"):
            script_text = script_tag.string or ""
            for pattern in SUSPICIOUS_JS_PATTERNS:
                if re.search(pattern, script_text, re.IGNORECASE):
                    _add({
                        "type": "Suspicious JavaScript",
                        "content": script_text[:1000],
                        "indicator": "Obfuscated JavaScript",
                        "confidence": "MEDIUM",
                        "reason": f"JS obfuscation pattern `{pattern}` — may dynamically inject hidden content",
                    })
                    break

        return candidates

    def _ocr_screenshot(self, screenshot_b64: str) -> List[Dict]:
        findings: List[Dict] = []
        if not OCR_AVAILABLE:
            return findings
        try:
            img_bytes = base64.b64decode(screenshot_b64)
            img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
            w, h = img.size
            upscaled = img.resize((int(w * 2.5), int(h * 2.5)), Image.LANCZOS)

            seen_texts = set()
            for config in ["--psm 3", "--psm 11"]:
                try:
                    text = pytesseract.image_to_string(upscaled, config=config).strip()
                    if text and text not in seen_texts and len(text) > 5:
                        seen_texts.add(text)
                except Exception:
                    pass

            combined = "\n".join(seen_texts)
            if combined and len(combined) > 10:
                findings.append({
                    "type": "Screenshot OCR",
                    "content": combined[:2000],
                    "indicator": "OCR Text from Page Screenshot",
                    "confidence": "LOW",
                    "reason": "Text extracted from rendered page screenshot — may include visually hidden content",
                })
        except Exception as e:
            logger.warning(f"OCR on screenshot failed: {e}")
        return findings

    def _analyze_redirects(self, original_url: str, redirects: List[str]) -> List[Dict]:
        findings: List[Dict] = []
        if len(redirects) > 3:
            findings.append({
                "type": "Redirect Chain",
                "content": " → ".join([original_url] + redirects[:10]),
                "indicator": "Suspicious Redirect Chain",
                "confidence": "MEDIUM",
                "reason": f"Page follows {len(redirects)} redirects — common in phishing/injection campaigns",
            })
        return findings

    def _error_result(self, url: str, error: str) -> Dict[str, Any]:
        return {
            "action": "ERROR",
            "risk_score": 0,
            "structured_indicators": [],
            "web_scan": {
                "url": url,
                "error": error,
                "screenshot_b64": None,
                "hidden_findings_count": 0,
                "ocr_findings_count": 0,
                "redirect_findings_count": 0,
            },
            "duration_ms": 0,
        }


web_scanner = WebScanner()
