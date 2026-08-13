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
        seen_labels = set()
        for rule in h_res.get("matched_rules", []):
            lbl = rule.get("label", "")
            if lbl in seen_labels:
                continue
            seen_labels.add(lbl)
            invisible_text_detected.append({
                "element": "body",
                "type": lbl,
                "text": rule.get("matched_text", ""),
                "reason": f"HTML Injection Threat: {lbl}"
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
        seen_labels = set()
        for rule in h_res.get("matched_rules", []):
            lbl = rule.get("label", "")
            if lbl in seen_labels:
                continue
            seen_labels.add(lbl)
            invisible_text_findings.append({
                "type": lbl,
                "text": rule.get("matched_text", ""),
                "reason": f"Prompt injection pattern detected: {lbl}"
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

    def scan_code(self, code_content: str, filename: str = "code_file.py") -> Dict[str, Any]:
        """
        Scans source code files (.py, .js, .ts, .jsx, .tsx, .java, .cpp, .c, .cs, .go, .rs, .sh, .php, .rb, .json, .yaml, .yml, .sql)
        for hidden prompt injections in comments/docstrings, code execution vulnerabilities, secrets, and malicious import payloads.
        """
        start_time = time.perf_counter()
        metadata_findings = []
        invisible_text_findings = []

        ext = os.path.splitext(filename)[1].upper().replace(".", "") or "CODE"

        # 1. Secret / API Key Hardcoding Inspection
        secret_matches = re.findall(r'(?i)(api[_-]?key|secret|password|auth[_-]?token|aws[_-]?secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{8,})["\']', code_content)
        for field, val in secret_matches:
            metadata_findings.append({
                "field": f"Hardcoded Secret ({field})",
                "value": f"{val[:6]}...",
                "reason": f"Hardcoded secret/credential detected in source code file '{filename}'"
            })

        # 2. Code Injection / Malicious Command Execution
        exec_patterns = [
            (r'os\.(system|popen|exec|spawn)', "OS Command Execution Call"),
            (r'subprocess\.(Popen|run|call|check_output)', "Subprocess Process Spawning"),
            (r'eval\s*\(', "Dynamic Eval Code Execution"),
            (r'exec\s*\(', "Dynamic Exec Code Execution"),
            (r'__import__\s*\(', "Dynamic Import Injection"),
            (r'rm\s+-rf', "Destructive Command Trigger"),
            (r'cat\s+/etc/passwd', "OS Password Probe")
        ]

        for pattern, label in exec_patterns:
            m = re.search(pattern, code_content)
            if m:
                invisible_text_findings.append({
                    "type": label,
                    "text": m.group(0),
                    "reason": f"Code Security Violation: {label} detected in '{filename}'"
                })

        # 3. Prompt Injections hidden inside Code Comments or Docstrings
        from app.services.heuristic_scanner import heuristic_scanner
        h_res = heuristic_scanner.scan(code_content)
        seen_labels = set()
        for rule in h_res.get("matched_rules", []):
            lbl = rule.get("label", "")
            if lbl in seen_labels:
                continue
            seen_labels.add(lbl)
            invisible_text_findings.append({
                "type": f"Code Injection: {lbl}",
                "text": rule.get("matched_text", ""),
                "reason": f"Prompt injection hidden in code comment/docstring: {lbl}"
            })

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return {
            "document_type": f"CODE_{ext}",
            "filename": filename,
            "metadata_findings": metadata_findings,
            "invisible_text_findings": invisible_text_findings,
            "extracted_text": code_content,
            "duration_ms": round(elapsed_ms, 3)
        }

    def scan_xml(self, xml_content: str, filename: str = "document.xml") -> Dict[str, Any]:
        """
        Scans XML documents for embedded prompt injections inside tags, comments, or attributes.
        """
        start_time = time.perf_counter()
        invisible_text_detected = []
        metadata_findings = []

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(xml_content, 'html.parser')

            # 1. XML comment inspection
            comments = soup.find_all(string=lambda text: isinstance(text, type(soup.comment)))
            for c in comments:
                c_str = str(c).strip()
                if c_str:
                    invisible_text_detected.append({
                        "element": "comment",
                        "text": c_str,
                        "reason": f"Prompt injection hidden inside XML comment tag in '{filename}'"
                    })

            # 2. Extract inner text from XML tags excluding XML declaration header
            tag_texts = []
            for tag in soup.find_all(True):
                t_str = tag.get_text().strip()
                if t_str and t_str not in tag_texts and not t_str.startswith("<?xml"):
                    tag_texts.append(t_str)

            body_text = "\n".join(tag_texts) if tag_texts else xml_content
        except Exception as err:
            logger.warning(f"XML scanner fallback: {err}")
            body_text = xml_content

        # Strip ALL XML/HTML tags including processing instructions (<?xml...?>, <!--...-->, <tag>)
        clean_text_payload = re.sub(r'<\?[^?]*\?>', ' ', body_text)          # strip <?xml ...?>
        clean_text_payload = re.sub(r'<!--[\s\S]*?-->', ' ', clean_text_payload)  # strip <!-- comments -->
        clean_text_payload = re.sub(r'<[^>]+>', ' ', clean_text_payload)        # strip remaining <tags>
        clean_text_payload = re.sub(r'\s+', ' ', clean_text_payload).strip()

        # Run heuristic scanner over XML body text
        from app.services.heuristic_scanner import heuristic_scanner
        h_res = heuristic_scanner.scan(clean_text_payload)
        seen_labels = set()
        for rule in h_res.get("matched_rules", []):
            lbl = rule.get("label", "")
            if lbl in seen_labels:
                continue
            seen_labels.add(lbl)
            invisible_text_detected.append({
                "element": "xml_tag",
                "type": lbl,
                "text": rule.get("matched_text", ""),
                "reason": f"XML Injection Threat: {lbl}"
            })

        # If no heuristic rules matched, pass the actual inner text of the XML element
        if not invisible_text_detected and clean_text_payload:
            invisible_text_detected.append({
                "element": "xml_payload",
                "text": clean_text_payload,
                "reason": "Prompt injection payload detected inside XML elements"
            })

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return {
            "document_type": "XML",
            "filename": filename,
            "metadata_findings": metadata_findings,
            "invisible_text_findings": invisible_text_detected,
            "extracted_text": clean_text_payload if clean_text_payload else re.sub(r'<[\s\S]*?>', ' ', xml_content).strip(),
            "duration_ms": round(elapsed_ms, 3)
        }

    def scan_image(self, file_bytes: bytes, filename: str = "image.png") -> Dict[str, Any]:
        """
        Scans images (.png, .jpg, .jpeg, .webp, .bmp, .tiff) for embedded prompt injections
        hidden in EXIF metadata, steganographic tags, or OCR-extracted text layer.
        """
        start_time = time.perf_counter()
        metadata_findings = []
        invisible_text_findings = []
        extracted_text_parts = []
        ext = os.path.splitext(filename)[1].upper().replace(".", "") or "IMAGE"

        try:
            from PIL import Image, ExifTags
            img = Image.open(io.BytesIO(file_bytes))

            # 1. EXIF & Info Metadata Inspection
            exif_data = {}
            try:
                raw_exif = img._getexif()
                if raw_exif:
                    for tag_id, val in raw_exif.items():
                        tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                        exif_data[tag_name] = str(val)
            except Exception:
                pass

            # Also check PIL image info dict
            for k, v in img.info.items():
                if isinstance(v, (str, bytes)):
                    exif_data[str(k)] = str(v)

            from app.services.heuristic_scanner import heuristic_scanner

            seen_exif_fields = set()
            # Non-instructional metadata strings (C2PA content credentials, ICC profiles, Adobe tags)
            PROVENANCE_KEYWORDS = ["c2pa", "digitalsourcetype", "trainedalgorithmicmedia", "icc_profile", "photoshop", "xmp"]

            for tag_name, val_str in exif_data.items():
                if tag_name in seen_exif_fields:
                    continue
                val_clean = val_str.strip()
                if len(val_clean) > 5:
                    val_lower = val_clean.lower()
                    # Skip C2PA provenance and standard metadata tags if they contain no explicit instruction override directives
                    is_provenance = any(p_kw in val_lower for p_kw in PROVENANCE_KEYWORDS)
                    has_instruction_directive = any(kw in val_lower for kw in ["ignore", "override", "system", "disregard", "secret", "jailbreak", "return strictly", "instruction"])
                    
                    if is_provenance and not has_instruction_directive:
                        continue

                    h_meta = heuristic_scanner.scan(val_clean)
                    if h_meta.get("matched_rules"):
                        seen_exif_fields.add(tag_name)
                        first_rule = h_meta["matched_rules"][0]
                        metadata_findings.append({
                            "field": f"EXIF:{tag_name}",
                            "value": val_clean[:150],
                            "reason": f"Prompt injection hidden inside Image EXIF metadata '{tag_name}': {first_rule.get('label')}"
                        })

            # 2. OCR Text Extraction (Pytesseract / Dual-Pass Enhanced OCR / Fallback)
            ocr_text = ""
            try:
                import pytesseract
                from PIL import ImageEnhance, ImageOps

                # Auto-locate Tesseract executable binary on Windows
                tess_paths = [
                    r'C:\Program Files\Tesseract-OCR\tesseract.exe',
                    r'C:\Program Files (x86)\Tesseract-OCR\tesseract.exe',
                    os.path.expanduser(r'~\AppData\Local\Programs\Tesseract-OCR\tesseract.exe')
                ]
                for p in tess_paths:
                    if os.path.exists(p):
                        pytesseract.pytesseract.tesseract_cmd = p
                        break

                # Pass 1: Standard OCR (Auto Page Segmentation)
                raw_ocr = pytesseract.image_to_string(img, config='--psm 3').strip()

                # Pass 2: Upscaled 2.5x + Sparse Text PSM 11 (Extracts tiny footer / margin text)
                try:
                    w, h = img.size
                    scaled_img = img.resize((int(w * 2.5), int(h * 2.5)), Image.Resampling.LANCZOS)
                    gray_img = scaled_img.convert('L')
                    
                    # Sparse text mode for small footer notes
                    sparse_ocr = pytesseract.image_to_string(gray_img, config='--psm 11').strip()
                except Exception:
                    sparse_ocr = ""

                # Pass 3: Contrast-Enhanced + PSM 6 (High contrast thresholding for faint/gray text)
                try:
                    enhancer = ImageEnhance.Contrast(gray_img)
                    contrast_img = enhancer.enhance(2.5)
                    contrast_ocr = pytesseract.image_to_string(contrast_img, config='--psm 6').strip()
                except Exception:
                    contrast_ocr = ""

                ocr_text = f"{raw_ocr}\n{sparse_ocr}\n{contrast_ocr}".strip()
            except Exception as ocr_err:
                logger.debug(f"Pytesseract OCR fallback: {ocr_err}")
                try:
                    # Fallback: simple printable string extraction from bytes if OCR engine not installed
                    printable = re.findall(r'[\x20-\x7E]{6,}', file_bytes.decode('latin-1', errors='ignore'))
                    # Exclude common image metadata headers and C2PA provenance strings from extracted body text
                    metadata_kws = ["photoshop", "adobe", "icc_profile", "exif", "jfif", "xmp", "c2pa", "digitalsourcetype", "trainedalgorithmicmedia"]
                    filtered = [p for p in printable if not any(kw in p.lower() for kw in metadata_kws)]
                    if filtered:
                        ocr_text = "\n".join(filtered[:20])
                except Exception:
                    pass

            if ocr_text:
                extracted_text_parts.append(ocr_text)

                # Scan OCR extracted text with heuristic security engine
                h_res = heuristic_scanner.scan(ocr_text)
                seen_labels = set()
                for rule in h_res.get("matched_rules", []):
                    lbl = rule.get("label", "")
                    if lbl in seen_labels:
                        continue
                    seen_labels.add(lbl)
                    invisible_text_findings.append({
                        "element": "image_ocr",
                        "type": f"Image OCR Injection ({lbl})",
                        "text": rule.get("matched_text", ""),
                        "reason": f"Prompt injection detected inside Image OCR text: {lbl}"
                    })

        except Exception as err:
            logger.warning(f"Image scanner error for '{filename}': {err}")

        final_extracted = "\n".join(extracted_text_parts).strip()
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return {
            "document_type": f"IMAGE_{ext}",
            "filename": filename,
            "metadata_findings": metadata_findings,
            "invisible_text_findings": invisible_text_findings,
            "extracted_text": final_extracted if final_extracted else f"Image document ({filename})",
            "duration_ms": round(elapsed_ms, 3)
        }

document_scanner = DocumentScanner()
