from fastapi import APIRouter, File, UploadFile, Form, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
from app.services.guardrail_pipeline import guardrail_pipeline
from app.services.document_scanner import document_scanner
from app.services.web_scanner import web_scanner
from app.services.pii_scanner_service import pii_scanner_service

router = APIRouter(prefix="/scan", tags=["Scan"])

class UrlScanRequest(BaseModel):
    url: str
    sensitivity_profile: Optional[str] = "BALANCED"

class TextScanRequest(BaseModel):
    prompt: str
    sensitivity_profile: Optional[str] = "BALANCED"
    custom_threshold: Optional[float] = None
    context: Optional[Dict[str, Any]] = None

class PiiScanRequest(BaseModel):
    text: str
    mask_mode: Optional[str] = "tag"

@router.post("/pii")
async def scan_pii(req: PiiScanRequest):
    """
    Scan text for PII data leakage using Isotonic/deberta-v3-base_finetuned_ai4privacy_v2
    combined with Verhoeff/Luhn checksum validators and regex recognizers.
    """
    if not req.text or not req.text.strip():
        raise HTTPException(status_code=400, detail="Input text cannot be empty.")
    
    result = pii_scanner_service.scan(text=req.text.strip(), mask_mode=req.mask_mode or "tag")
    return result

@router.post("/text")
async def scan_text_prompt(req: TextScanRequest):
    """Scan a chat prompt or text input across all 3 security layers (<100ms latency budget)."""
    if not req.prompt:
        raise HTTPException(status_code=400, detail="Prompt text cannot be empty.")
    
    result = guardrail_pipeline.evaluate(
        raw_text=req.prompt,
        sensitivity_profile=req.sensitivity_profile or "BALANCED",
        custom_threshold=req.custom_threshold,
        context=req.context
    )
    return result


@router.post("/document")
async def scan_document_file(
    file: UploadFile = File(...),
    sensitivity_profile: str = Form("BALANCED"),
    custom_threshold: Optional[float] = Form(None)
):
    """
    Scan an uploaded document (PDF, DOCX, HTML, TXT) for hidden instructions,
    invisible white text, metadata prompt payloads, and steganography.
    """
    file_bytes = await file.read()
    filename = file.filename or "uploaded_document"
    ext = filename.split(".")[-1].lower()

    CODE_EXTENSIONS = {"py", "js", "ts", "jsx", "tsx", "java", "cpp", "c", "cs", "go", "rs", "sh", "php", "rb", "json", "yaml", "yml", "xml", "sql"}
    IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "bmp", "tiff"}

    if ext == "pdf":
        doc_meta = document_scanner.scan_pdf(file_bytes, filename)
    elif ext in ["docx", "doc"]:
        doc_meta = document_scanner.scan_docx(file_bytes, filename)
    elif ext in ["html", "htm"]:
        doc_meta = document_scanner.scan_html(file_bytes.decode('utf-8', errors='ignore'), filename)
    elif ext == "xml":
        doc_meta = document_scanner.scan_xml(file_bytes.decode('utf-8', errors='ignore'), filename)
    elif ext in IMAGE_EXTENSIONS:
        doc_meta = document_scanner.scan_image(file_bytes, filename)
    elif ext in CODE_EXTENSIONS:
        doc_meta = document_scanner.scan_code(file_bytes.decode('utf-8', errors='ignore'), filename)
    else:
        doc_meta = document_scanner.scan_text(file_bytes.decode('utf-8', errors='ignore'), filename)

    # Evaluate the extracted body text + document findings through the security pipeline
    result = guardrail_pipeline.evaluate(
        raw_text=doc_meta["extracted_text"],
        sensitivity_profile=sensitivity_profile,
        custom_threshold=custom_threshold,
        document_meta=doc_meta
    )
    
    return result


@router.post("/url")
async def scan_url(req: UrlScanRequest):
    """
    Scan a public URL for indirect prompt injection threats.
    Fetches the page via Playwright, analyzes hidden DOM content, CSS tricks,
    HTML comments, attribute payloads, and runs OCR on the rendered screenshot.
    """
    if not req.url or not req.url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    url = req.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        result = await web_scanner.scan_url(url, sensitivity_profile=req.sensitivity_profile or "BALANCED")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Web scan failed: {str(e)}")

    return result
