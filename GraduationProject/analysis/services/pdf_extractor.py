"""
PDF metadata and XMP extraction service.

Extracts from PDF files:
  - Standard metadata (title, author, creator, producer, dates)
  - XMP identifiers (DocumentID, InstanceID, OriginalDocumentID)
  - Structural features (page count, embedded objects, JavaScript, URLs)
  - Entropy calculation for anomaly detection

XMP identifiers are the key innovation from J. Smith's research:
  "Malicious campaigns often reuse embedded lure images with
   persistent Adobe XMP identifiers. These IDs can cluster
   related malicious documents into families."
  (Report Section 2.3)

This maps to "Metadata/XMP Extraction" in the data flow diagram.
"""

import logging
import math
import re
from collections import Counter
from io import BytesIO
from pathlib import Path

logger = logging.getLogger("analysis")

# URL pattern for extraction
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\')\]}>]{3,}',
    re.IGNORECASE,
)


def extract_pdf_metadata(file_path: str) -> dict:
    """
    Extract all metadata and features from a PDF file.

    Returns a dict with keys: xmp, metadata, structural, urls, extraction_status
    """
    try:
        from PyPDF2 import PdfReader
    except ImportError:
        logger.error("PyPDF2 not installed")
        return _empty_result("PyPDF2 not installed")

    result = {
        "xmp": _empty_xmp(),
        "metadata": _empty_metadata(),
        "structural": _empty_structural(),
        "urls": [],
        "extraction_status": "success",
    }

    try:
        reader = PdfReader(file_path)

        # --- Standard metadata ---
        result["metadata"] = _extract_pdf_standard_metadata(reader)

        # --- XMP metadata ---
        result["xmp"] = _extract_pdf_xmp(reader, file_path)

        # --- Structural features ---
        result["structural"] = _extract_pdf_structural(reader, file_path)

        # --- URLs ---
        result["urls"] = _extract_pdf_urls(reader)

        # Sync URL counts into structural (text extraction finds more than raw bytes)
        if result["urls"]:
            result["structural"]["has_urls"] = True
            result["structural"]["url_count"] = max(
                result["structural"]["url_count"], len(result["urls"])
            )

        logger.info("PDF metadata extracted: %s", Path(file_path).name)

    except Exception as e:
        logger.error("PDF extraction failed for %s: %s", file_path, str(e))
        result["extraction_status"] = f"partial_failure: {str(e)}"

    return result


def _extract_pdf_standard_metadata(reader) -> dict:
    """Extract standard PDF metadata from the document info dictionary."""
    meta = _empty_metadata()

    try:
        info = reader.metadata
        if info:
            meta["title"] = str(info.get("/Title", "") or "")
            meta["author"] = str(info.get("/Author", "") or "")
            meta["creator"] = str(info.get("/Creator", "") or "")
            meta["producer"] = str(info.get("/Producer", "") or "")
            meta["subject"] = str(info.get("/Subject", "") or "")

            # Parse dates
            creation = info.get("/CreationDate")
            if creation:
                meta["creation_date"] = str(creation)

            modification = info.get("/ModDate")
            if modification:
                meta["modification_date"] = str(modification)
    except Exception as e:
        logger.warning("Could not extract PDF standard metadata: %s", e)

    return meta


def _extract_pdf_xmp(reader, file_path: str) -> dict:
    """
    Extract XMP identifiers from PDF.

    XMP data is stored as XML inside the PDF. Key fields:
      - xmpMM:DocumentID — persistent across edits of the same document
      - xmpMM:InstanceID — changes each time the document is saved
      - xmpMM:OriginalDocumentID — original source document ID

    These are the "serial numbers" that link campaign documents together.
    """
    xmp = _empty_xmp()

    try:
        # Method 1: PyPDF2's xmp_metadata property
        xmp_data = reader.xmp_metadata
        if xmp_data:
            # DocumentID
            doc_id = getattr(xmp_data, "xmpmm_document_id", None)
            if doc_id:
                xmp["document_id"] = str(doc_id)

            # InstanceID
            instance_id = getattr(xmp_data, "xmpmm_instance_id", None)
            if instance_id:
                xmp["instance_id"] = str(instance_id)

            # Additional XMP fields
            dc_creator = getattr(xmp_data, "dc_creator", None)
            if dc_creator:
                xmp["dc_creator"] = [str(c) for c in dc_creator] if dc_creator else []

            dc_title = getattr(xmp_data, "dc_title", None)
            if dc_title:
                xmp["dc_title"] = str(dc_title)

            dc_description = getattr(xmp_data, "dc_description", None)
            if dc_description:
                xmp["dc_description"] = str(dc_description)

            # Producer/creator tool
            xmp_creator_tool = getattr(xmp_data, "xmp_creator_tool", None)
            if xmp_creator_tool:
                xmp["creator_tool"] = str(xmp_creator_tool)

            xmp["xmp_present"] = True

    except Exception as e:
        logger.warning("PyPDF2 XMP extraction failed: %s", e)

    # Method 2: Raw XML parsing for fields PyPDF2 might miss
    try:
        xmp = _extract_xmp_from_raw_xml(file_path, xmp)
    except Exception as e:
        logger.warning("Raw XMP XML extraction failed: %s", e)

    return xmp


def _extract_xmp_from_raw_xml(file_path: str, xmp: dict) -> dict:
    """
    Parse raw XMP XML from the PDF file bytes.

    Falls back to regex-based extraction from the raw file content
    to catch XMP data that PyPDF2's parser might miss.
    """
    try:
        from lxml import etree
    except ImportError:
        logger.warning("lxml not installed, skipping raw XMP extraction")
        return xmp

    with open(file_path, "rb") as f:
        content = f.read()

    # Find XMP packet boundaries
    xmp_start = content.find(b"<?xpacket begin=")
    xmp_end = content.find(b"<?xpacket end=")

    if xmp_start == -1 or xmp_end == -1:
        # Try alternate XMP markers
        xmp_start = content.find(b"<x:xmpmeta")
        xmp_end = content.find(b"</x:xmpmeta>")
        if xmp_end != -1:
            xmp_end += len(b"</x:xmpmeta>")

    if xmp_start == -1 or xmp_end == -1:
        return xmp

    xmp_bytes = content[xmp_start:xmp_end + len(b'<?xpacket end="w"?>')]

    # Namespace mappings
    namespaces = {
        "xmpMM": "http://ns.adobe.com/xap/1.0/mm/",
        "xmp": "http://ns.adobe.com/xap/1.0/",
        "dc": "http://purl.org/dc/elements/1.1/",
        "pdf": "http://ns.adobe.com/pdf/1.3/",
        "pdfx": "http://ns.adobe.com/pdfx/1.3/",
        "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    }

    try:
        root = etree.fromstring(xmp_bytes)

        # Extract XMP MM fields
        for field, xpath in [
            ("document_id", ".//xmpMM:DocumentID"),
            ("instance_id", ".//xmpMM:InstanceID"),
            ("original_document_id", ".//xmpMM:OriginalDocumentID"),
            ("version_id", ".//xmpMM:VersionID"),
        ]:
            elements = root.xpath(xpath, namespaces=namespaces)
            if elements and elements[0].text:
                xmp[field] = elements[0].text.strip()

        # Extract derived from references
        derived_from = root.xpath(
            ".//xmpMM:DerivedFrom//@*", namespaces=namespaces
        )
        if derived_from:
            xmp["derived_from"] = [str(d) for d in derived_from]

        xmp["xmp_present"] = True
        xmp["raw_xmp_size"] = len(xmp_bytes)

    except etree.XMLSyntaxError as e:
        logger.warning("XMP XML parse error: %s", e)
        # Fallback: regex extraction
        xmp = _regex_extract_xmp_fields(xmp_bytes, xmp)

    return xmp


def _regex_extract_xmp_fields(xmp_bytes: bytes, xmp: dict) -> dict:
    """Regex fallback for extracting XMP fields from malformed XML."""
    patterns = {
        "document_id": rb"<xmpMM:DocumentID>(.*?)</xmpMM:DocumentID>",
        "instance_id": rb"<xmpMM:InstanceID>(.*?)</xmpMM:InstanceID>",
        "original_document_id": rb"<xmpMM:OriginalDocumentID>(.*?)</xmpMM:OriginalDocumentID>",
    }

    for field, pattern in patterns.items():
        match = re.search(pattern, xmp_bytes)
        if match and not xmp.get(field):
            xmp[field] = match.group(1).decode("utf-8", errors="replace").strip()

    if any(xmp.get(f) for f in patterns):
        xmp["xmp_present"] = True

    return xmp


def _extract_pdf_structural(reader, file_path: str) -> dict:
    """
    Extract structural features from PDF.

    These features are used by the ML model to detect anomalies:
      - Page count, file size
      - JavaScript presence (common in malicious PDFs)
      - Embedded files/objects
      - Form fields (can trigger actions)
      - Entropy (high entropy may indicate obfuscation)
    """
    structural = _empty_structural()

    try:
        structural["page_count"] = len(reader.pages)
    except Exception:
        pass

    try:
        structural["file_size"] = Path(file_path).stat().st_size
    except Exception:
        pass

    # Check for JavaScript
    try:
        with open(file_path, "rb") as f:
            raw = f.read()

        js_indicators = [b"/JavaScript", b"/JS ", b"/JS(", b"app.alert", b"eval("]
        js_count = sum(1 for ind in js_indicators if ind in raw)
        structural["has_javascript"] = js_count > 0
        structural["javascript_indicator_count"] = js_count

        # Check for auto-open actions
        action_indicators = [b"/OpenAction", b"/AA", b"/Launch", b"/SubmitForm", b"/ImportData"]
        action_count = sum(1 for ind in action_indicators if ind in raw)
        structural["has_auto_actions"] = action_count > 0
        structural["auto_action_count"] = action_count

        # Check for embedded files
        embedded_indicators = [b"/EmbeddedFile", b"/FileAttachment"]
        structural["has_embedded_files"] = any(ind in raw for ind in embedded_indicators)

        # Count streams (potential embedded objects)
        structural["stream_count"] = raw.count(b"stream\r\n") + raw.count(b"stream\n")

        # Entropy
        structural["entropy"] = _calculate_entropy(raw)

        # URL count
        urls = URL_PATTERN.findall(raw.decode("latin-1", errors="replace"))
        structural["url_count"] = len(urls)
        structural["has_urls"] = len(urls) > 0

    except Exception as e:
        logger.warning("PDF structural analysis error: %s", e)

    return structural


def _extract_pdf_urls(reader) -> list[str]:
    """Extract all URLs found in the PDF."""
    urls = set()

    try:
        for page in reader.pages:
            text = page.extract_text() or ""
            found = URL_PATTERN.findall(text)
            urls.update(found)

            # Check annotations for links
            if "/Annots" in page:
                annotations = page["/Annots"]
                for annot in annotations:
                    annot_obj = annot.get_object()
                    if "/A" in annot_obj:
                        action = annot_obj["/A"]
                        if "/URI" in action:
                            urls.add(str(action["/URI"]))
    except Exception as e:
        logger.warning("URL extraction error: %s", e)

    return list(urls)[:100]  # cap at 100 URLs


def _calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of the file.

    High entropy (>7.5) may indicate encryption or obfuscation.
    Normal documents typically have entropy between 4.0-6.5.
    """
    if not data:
        return 0.0

    counter = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return round(entropy, 4)


# -------------------------------------------------------------------------
# Empty/default value helpers
# -------------------------------------------------------------------------

def _empty_xmp() -> dict:
    return {
        "document_id": "",
        "instance_id": "",
        "original_document_id": "",
        "version_id": "",
        "derived_from": [],
        "dc_creator": [],
        "dc_title": "",
        "dc_description": "",
        "creator_tool": "",
        "xmp_present": False,
        "raw_xmp_size": 0,
    }


def _empty_metadata() -> dict:
    return {
        "title": "",
        "author": "",
        "creator": "",
        "producer": "",
        "subject": "",
        "creation_date": "",
        "modification_date": "",
    }


def _empty_structural() -> dict:
    return {
        "page_count": 0,
        "file_size": 0,
        "has_javascript": False,
        "javascript_indicator_count": 0,
        "has_auto_actions": False,
        "auto_action_count": 0,
        "has_embedded_files": False,
        "stream_count": 0,
        "has_macros": False,
        "macro_count": 0,
        "has_embedded_objects": False,
        "embedded_object_count": 0,
        "has_urls": False,
        "url_count": 0,
        "entropy": 0.0,
    }


def _empty_result(reason: str = "") -> dict:
    return {
        "xmp": _empty_xmp(),
        "metadata": _empty_metadata(),
        "structural": _empty_structural(),
        "urls": [],
        "extraction_status": f"failed: {reason}" if reason else "failed",
    }
