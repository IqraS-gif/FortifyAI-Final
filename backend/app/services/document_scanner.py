import re
import os
import io
import time
import logging
from typing import Dict, List, Any, Tuple

logger = logging.getLogger("fortifyai.doc_scanner")

class DocumentScanner:
    """
    Layer 3: Document-Level Security Scanner
    Scans PDFs, DOCX files, HTML web pages, and raw text for hidden prompt injections,
    invisible text (white font on white background, 0pt font size), metadata fields,
    and steganographic payload injections.
    """

    def scan_pdf(self, file_bytes: bytes, filename: str) -> Dict[str, Any]:
        start_time = time.perf_counter()
        findings = []
        invisible_text_detected = []
        metadata_findings = []
        body_text_parts = []

        try:
            import pypdf
            reader = pypdf.PdfReader(io.BytesIO(file_bytes))

            # 1. Metadata Inspection
            if reader.metadata:
                for key in ["/Title", "/Author", "/Subject", "/Keywords", "/Creator", "/Producer"]:
                    val = reader.metadata.get(key)
                    if val and isinstance(val, str):
                        # Scan metadata value for injection directives
                        if re.search(r"(ignore|override|system|secret|jailbreak|disregard)", val, re.IGNORECASE):
                            metadata_findings.append({
                                "field": key.replace("/", ""),
                                "value": val,
                                "reason": f"Malicious prompt injection hidden inside PDF Metadata '{key}' field"
                            })

            # 2. Page & Font Structure / Invisible Text Inspection
            for page_idx, page in enumerate(reader.pages):
                text = page.extract_text() or ""
                body_text_parts.append(text)

                # Advanced Font & Color Analysis if available
                # Search for font size <= 1pt or RGB color matching white (#FFFFFF / 1.0, 1.0, 1.0)
                try:
                    def visitor_body(text, cm, tm, fontDict, fontSize):
                        if fontSize and fontSize <= 1.5 and text.strip():
                            invisible_text_detected.append({
                                "page": page_idx + 1,
                                "font_size": fontSize,
                                "text": text.strip(),
                                "reason": f"Microscopic/invisible text (font size {fontSize}pt) detected on page {page_idx + 1}"
                            })

                    page.extract_text(visitor_text=visitor_body)
                except Exception:
                    pass

                # Check for white-on-white text pattern in PDF streams (e.g. 1 1 1 rg or 1 1 1 RG followed by text)
                raw_contents = str(page.get_contents())
                if re.search(r"(1\s+1\s+1\s+rg|1\s+1\s+1\s+RG|#FFFFFF)", raw_contents, re.IGNORECASE):
                    if re.search(r"(ignore|override|system|prompt|secret|rubric)", text, re.IGNORECASE):
                        invisible_text_detected.append({
                            "page": page_idx + 1,
                            "text": text[:120],
                            "reason": f"Invisible white font payload detected on PDF Page {page_idx + 1}"
                        })

        except Exception as err:
            logger.warning(f"PDF parsing fallback: {err}")
            text_fallback = file_bytes.decode('utf-8', errors='ignore')
            body_text_parts.append(text_fallback)

        full_body_text = "\n".join(body_text_parts)
        
        # 3. Direct Heuristic Scan over Extracted Document Text
        from app.services.heuristic_scanner import heuristic_scanner
        h_res = heuristic_scanner.scan(full_body_text)
        for rule in h_res.get("matched_rules", []):
            invisible_text_detected.append({
                "page": 1,
                "text": rule.get("matched_text", "")[:100],
                "reason": f"Document Prompt Injection Threat Detected: {rule.get('label')} ('{rule.get('matched_text')}')"
            })

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return {
            "document_type": "PDF",
            "filename": filename,
            "metadata_findings": metadata_findings,
            "invisible_text_findings": invisible_text_detected,
            "extracted_text": full_body_text,
            "duration_ms": round(elapsed_ms, 3)
        }

    def scan_docx(self, file_bytes: bytes, filename: str) -> Dict[str, Any]:
        start_time = time.perf_counter()
        metadata_findings = []
        invisible_text_detected = []
        extracted_paragraphs = []

        try:
            import docx
            doc = docx.Document(io.BytesIO(file_bytes))

            # 1. Core Properties Scanning
            cp = doc.core_properties
            for prop_name, prop_val in [("title", cp.title), ("author", cp.author), ("subject", cp.subject), ("keywords", cp.keywords), ("comments", cp.comments)]:
                if prop_val and re.search(r"(ignore|override|system|secret|jailbreak)", prop_val, re.IGNORECASE):
                    metadata_findings.append({
                        "field": prop_name,
                        "value": prop_val,
                        "reason": f"Malicious prompt payload hidden in DOCX metadata field '{prop_name}'"
                    })

            # 2. Hidden text XML tag inspection (<w:vanish/> or white color font)
            for p_idx, p in enumerate(doc.paragraphs):
                extracted_paragraphs.append(p.text)
                for run in p.runs:
                    # Check DOCX hidden text XML attribute
                    if run._element.xpath('.//w:vanish') or (run.font.color and run.font.color.rgb == docx.shared.RGBColor(255, 255, 255)):
                        if run.text.strip():
                            invisible_text_detected.append({
                                "paragraph": p_idx + 1,
                                "text": run.text.strip(),
                                "reason": f"Hidden font text (<w:vanish> / white font) detected in paragraph {p_idx + 1}"
                            })

        except Exception as err:
            logger.warning(f"DOCX scanner fallback: {err}")

        full_text = "\n".join(extracted_paragraphs)
        from app.services.heuristic_scanner import heuristic_scanner
        h_res = heuristic_scanner.scan(full_text)
        for rule in h_res.get("matched_rules", []):
            invisible_text_detected.append({
                "paragraph": 1,
                "text": rule.get("matched_text", "")[:100],
                "reason": f"Document Threat Detected: {rule.get('label')} ('{rule.get('matched_text')}')"
            })

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return {
            "document_type": "DOCX",
            "filename": filename,
            "metadata_findings": metadata_findings,
            "invisible_text_findings": invisible_text_detected,
            "extracted_text": full_text,
            "duration_ms": round(elapsed_ms, 3)
        }

    def scan_html(self, html_content: str, filename: str = "web_content.html") -> Dict[str, Any]:
        start_time = time.perf_counter()
        invisible_text_detected = []
        metadata_findings = []

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_content, 'html.parser')

            # 1. Meta tag inspection
            for meta in soup.find_all('meta'):
                content = meta.get('content', '')
                name = meta.get('name', '') or meta.get('property', '')
                if content and re.search(r"(ignore|override|system|secret|jailbreak)", content, re.IGNORECASE):
                    metadata_findings.append({
                        "field": f"meta[{name}]",
                        "value": content,
                        "reason": f"Prompt injection hidden inside HTML meta tag '{name}'"
                    })

            # 2. Hidden CSS element inspection (display:none, visibility:hidden, font-size:0, opacity:0)
            hidden_elements = soup.find_all(style=re.compile(r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0|color\s*:\s*transparent)", re.IGNORECASE))
            for elem in hidden_elements:
                elem_text = elem.get_text().strip()
                if elem_text:
                    invisible_text_detected.append({
                        "element": elem.name,
                        "style": elem.get('style'),
                        "text": elem_text[:150],
                        "reason": f"Hidden HTML element (CSS hidden style) containing payload text"
                    })

            # 3. HTML comment tags
            comments = soup.find_all(string=lambda text: isinstance(text, type(soup.comment)))
            for c in comments:
                if re.search(r"(ignore|override|system|secret|prompt|rubric)", c, re.IGNORECASE):
                    invisible_text_detected.append({
                        "element": "comment",
                        "text": c.strip(),
                        "reason": "Prompt injection payload hidden inside HTML comment block"
                    })

            body_text = soup.get_text()
        except Exception as err:
            logger.warning(f"HTML scanner fallback: {err}")
            body_text = html_content

        from app.services.heuristic_scanner import heuristic_scanner
        h_res = heuristic_scanner.scan(body_text)
        for rule in h_res.get("matched_rules", []):
            invisible_text_detected.append({
                "element": "body",
                "text": rule.get("matched_text", "")[:100],
                "reason": f"HTML Injection Threat: {rule.get('label')} ('{rule.get('matched_text')}')"
            })

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return {
            "document_type": "HTML",
            "filename": filename,
            "metadata_findings": metadata_findings,
            "invisible_text_findings": invisible_text_detected,
            "extracted_text": body_text,
            "duration_ms": round(elapsed_ms, 3)
        }

    def scan_text(self, text_content: str, filename: str = "document.txt") -> Dict[str, Any]:
        start_time = time.perf_counter()
        invisible_text_findings = []
        
        # Steganographic Unicode directionality tricks (e.g. \u202E Right-to-Left Override)
        if re.search(r'[\u202E\u202D\u202A\u202B\u2066\u2067\u2068]', text_content):
            invisible_text_findings.append({
                "type": "Unicode BiDi Override",
                "text": "Unicode Right-to-Left Override Characters Present",
                "reason": "Steganographic BIDI override characters used to visually alter document text"
            })

        from app.services.heuristic_scanner import heuristic_scanner
        h_res = heuristic_scanner.scan(text_content)
        for rule in h_res.get("matched_rules", []):
            invisible_text_findings.append({
                "type": rule.get("label"),
                "text": rule.get("matched_text", "")[:100],
                "reason": f"Document Prompt Injection Threat Detected: {rule.get('label')} ('{rule.get('matched_text')}')"
            })

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return {
            "document_type": "TXT",
            "filename": filename,
            "metadata_findings": [],
            "invisible_text_findings": invisible_text_findings,
            "extracted_text": text_content,
            "duration_ms": round(elapsed_ms, 3)
        }

document_scanner = DocumentScanner()
