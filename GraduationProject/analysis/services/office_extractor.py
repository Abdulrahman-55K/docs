"""
Office document (OOXML) metadata and XMP extraction service.

Extracts from DOCX, XLSX, PPTX files:
  - Standard metadata (title, author, creator, dates)
  - XMP identifiers from custom XML parts
  - Structural features (macros, embedded objects, URLs)
  - Entropy calculation

OOXML files are ZIP archives containing XML parts:
  - docProps/core.xml     → standard metadata
  - docProps/app.xml      → application metadata
  - docProps/custom.xml   → custom properties
  - [Content_Types].xml   → content type manifest
  - word/vbaProject.bin   → VBA macros (if present)

This maps to "Metadata/XMP Extraction" in the data flow diagram.
"""

import logging
import math
import re
import zipfile
from collections import Counter
from pathlib import Path

logger = logging.getLogger("analysis")

URL_PATTERN = re.compile(
    r'https?://[^\s<>"\')\]}>]{3,}',
    re.IGNORECASE,
)

# Namespaces used in OOXML
OOXML_NS = {
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "dcmitype": "http://purl.org/dc/dcmitype/",
    "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
    "vt": "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes",
    "xmpMM": "http://ns.adobe.com/xap/1.0/mm/",
    "xmp": "http://ns.adobe.com/xap/1.0/",
    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
}


def extract_office_metadata(file_path: str) -> dict:
    """
    Extract all metadata and features from an Office document.

    Handles DOCX, XLSX, and PPTX (all are OOXML ZIP archives).
    Returns a dict with keys: xmp, metadata, structural, urls, extraction_status
    """
    result = {
        "xmp": _empty_xmp(),
        "metadata": _empty_metadata(),
        "structural": _empty_structural(),
        "urls": [],
        "extraction_status": "success",
    }

    try:
        if not zipfile.is_zipfile(file_path):
            result["extraction_status"] = "failed: not a valid ZIP/OOXML file"
            return result

        with zipfile.ZipFile(file_path, "r") as zf:
            # --- Standard metadata from core.xml ---
            result["metadata"] = _extract_core_metadata(zf)

            # --- XMP from custom XML parts ---
            result["xmp"] = _extract_office_xmp(zf)

            # --- Structural features ---
            result["structural"] = _extract_office_structural(zf, file_path)

            # --- URLs ---
            result["urls"] = _extract_office_urls(zf)

        logger.info("Office metadata extracted: %s", Path(file_path).name)

    except zipfile.BadZipFile:
        result["extraction_status"] = "failed: corrupted ZIP archive"
        logger.error("Bad ZIP file: %s", file_path)
    except Exception as e:
        result["extraction_status"] = f"partial_failure: {str(e)}"
        logger.error("Office extraction failed for %s: %s", file_path, str(e))

    return result


def _extract_core_metadata(zf: zipfile.ZipFile) -> dict:
    """
    Extract standard metadata from docProps/core.xml.

    This file contains Dublin Core metadata fields.
    """
    meta = _empty_metadata()

    try:
        from lxml import etree
    except ImportError:
        logger.warning("lxml not installed, skipping core.xml parsing")
        return meta

    if "docProps/core.xml" not in zf.namelist():
        return meta

    try:
        core_xml = zf.read("docProps/core.xml")
        root = etree.fromstring(core_xml)

        field_map = {
            "title": ".//dc:title",
            "author": ".//dc:creator",
            "subject": ".//dc:subject",
            "creator": ".//dc:creator",
            "creation_date": ".//dcterms:created",
            "modification_date": ".//dcterms:modified",
        }

        for field, xpath in field_map.items():
            elements = root.xpath(xpath, namespaces=OOXML_NS)
            if elements and elements[0].text:
                meta[field] = elements[0].text.strip()

        # Also check for lastModifiedBy
        last_modified = root.xpath(".//cp:lastModifiedBy", namespaces=OOXML_NS)
        if last_modified and last_modified[0].text:
            meta["last_modified_by"] = last_modified[0].text.strip()

    except Exception as e:
        logger.warning("core.xml parse error: %s", e)

    # Also extract app.xml for producer/application info
    if "docProps/app.xml" in zf.namelist():
        try:
            app_xml = zf.read("docProps/app.xml")
            root = etree.fromstring(app_xml)

            app_name = root.xpath(".//ep:Application", namespaces=OOXML_NS)
            if app_name and app_name[0].text:
                meta["producer"] = app_name[0].text.strip()

            app_version = root.xpath(".//ep:AppVersion", namespaces=OOXML_NS)
            if app_version and app_version[0].text:
                meta["app_version"] = app_version[0].text.strip()

        except Exception as e:
            logger.warning("app.xml parse error: %s", e)

    return meta


def _extract_office_xmp(zf: zipfile.ZipFile) -> dict:
    """
    Extract XMP identifiers from Office documents.

    XMP data can be found in:
      - docProps/custom.xml (custom properties)
      - Embedded XMP streams in image parts
      - Custom XML parts
    """
    xmp = _empty_xmp()

    try:
        from lxml import etree
    except ImportError:
        return xmp

    # --- Check custom.xml for XMP-like properties ---
    if "docProps/custom.xml" in zf.namelist():
        try:
            custom_xml = zf.read("docProps/custom.xml")
            root = etree.fromstring(custom_xml)

            # Custom properties may contain XMP identifiers
            for prop in root.iter():
                name = prop.get("name", "").lower()
                if "documentid" in name and prop.text:
                    xmp["document_id"] = prop.text.strip()
                elif "instanceid" in name and prop.text:
                    xmp["instance_id"] = prop.text.strip()
        except Exception as e:
            logger.warning("custom.xml parse error: %s", e)

    # --- Scan all XML parts for XMP packets ---
    for name in zf.namelist():
        if not name.endswith(".xml") and not name.endswith(".rels"):
            continue

        try:
            content = zf.read(name)

            # Quick check for XMP markers
            if b"xmpMM:" not in content and b"xmp:" not in content:
                continue

            root = etree.fromstring(content)

            for field, xpath in [
                ("document_id", ".//xmpMM:DocumentID"),
                ("instance_id", ".//xmpMM:InstanceID"),
                ("original_document_id", ".//xmpMM:OriginalDocumentID"),
            ]:
                elements = root.xpath(xpath, namespaces=OOXML_NS)
                if elements and elements[0].text and not xmp.get(field):
                    xmp[field] = elements[0].text.strip()

            if any(xmp.get(f) for f in ["document_id", "instance_id"]):
                xmp["xmp_present"] = True

        except Exception:
            continue

    # --- Scan embedded images for XMP data ---
    xmp = _scan_embedded_images_for_xmp(zf, xmp)

    return xmp


def _scan_embedded_images_for_xmp(zf: zipfile.ZipFile, xmp: dict) -> dict:
    """
    Scan embedded images inside the Office doc for XMP metadata.

    This is the key insight from Smith's research:
    "Malicious campaigns reuse lure images that carry persistent
     XMP identifiers across many different documents."

    Images in OOXML live under word/media/, ppt/media/, xl/media/
    """
    image_extensions = (".png", ".jpg", ".jpeg", ".tiff", ".gif")

    for name in zf.namelist():
        if not any(name.lower().endswith(ext) for ext in image_extensions):
            continue

        try:
            img_data = zf.read(name)

            # Look for XMP packet in image bytes
            xmp_start = img_data.find(b"<?xpacket begin=")
            if xmp_start == -1:
                xmp_start = img_data.find(b"<x:xmpmeta")

            if xmp_start == -1:
                continue

            xmp_end = img_data.find(b"<?xpacket end=", xmp_start)
            if xmp_end == -1:
                xmp_end = img_data.find(b"</x:xmpmeta>", xmp_start)
                if xmp_end != -1:
                    xmp_end += len(b"</x:xmpmeta>")

            if xmp_end == -1:
                continue

            xmp_bytes = img_data[xmp_start:xmp_end + 30]

            # Parse XMP from image
            from lxml import etree
            try:
                root = etree.fromstring(xmp_bytes)

                ns = {
                    "xmpMM": "http://ns.adobe.com/xap/1.0/mm/",
                    "xmp": "http://ns.adobe.com/xap/1.0/",
                }

                for field, xpath in [
                    ("document_id", ".//xmpMM:DocumentID"),
                    ("instance_id", ".//xmpMM:InstanceID"),
                    ("original_document_id", ".//xmpMM:OriginalDocumentID"),
                ]:
                    elements = root.xpath(xpath, namespaces=ns)
                    if elements and elements[0].text:
                        value = elements[0].text.strip()
                        if not xmp.get(field):
                            xmp[field] = value

                        # Track all image XMP IDs for campaign linking
                        if "image_xmp_ids" not in xmp:
                            xmp["image_xmp_ids"] = []
                        xmp["image_xmp_ids"].append({
                            "image": name,
                            "field": field,
                            "value": value,
                        })

                xmp["xmp_present"] = True

            except etree.XMLSyntaxError:
                # Fallback: regex
                for field, pattern in [
                    ("document_id", rb"<xmpMM:DocumentID>(.*?)</xmpMM:DocumentID>"),
                    ("instance_id", rb"<xmpMM:InstanceID>(.*?)</xmpMM:InstanceID>"),
                ]:
                    match = re.search(pattern, xmp_bytes)
                    if match and not xmp.get(field):
                        xmp[field] = match.group(1).decode("utf-8", errors="replace").strip()
                        xmp["xmp_present"] = True

        except Exception as e:
            logger.debug("Image XMP scan error for %s: %s", name, e)
            continue

    return xmp


def _extract_office_structural(zf: zipfile.ZipFile, file_path: str) -> dict:
    """
    Extract structural features from Office documents.

    Checks for:
      - VBA macros (vbaProject.bin)
      - Embedded OLE objects
      - External relationships (template injection)
      - ActiveX controls
      - File entropy
    """
    structural = _empty_structural()

    try:
        structural["file_size"] = Path(file_path).stat().st_size
    except Exception:
        pass

    names = zf.namelist()

    # --- Macro detection ---
    macro_indicators = ["vbaProject.bin", "word/vbaProject.bin",
                        "xl/vbaProject.bin", "ppt/vbaProject.bin"]
    macro_files = [n for n in names if any(n.endswith(m) or m in n for m in macro_indicators)]
    structural["has_macros"] = len(macro_files) > 0
    structural["macro_count"] = len(macro_files)
    structural["macro_files"] = macro_files

    # --- Embedded OLE objects ---
    ole_indicators = ["oleObject", "embeddings/", "activeX/"]
    embedded = [n for n in names if any(ind in n for ind in ole_indicators)]
    structural["has_embedded_objects"] = len(embedded) > 0
    structural["embedded_object_count"] = len(embedded)

    # --- External relationships (template injection) ---
    external_refs = []
    for name in names:
        if name.endswith(".rels"):
            try:
                rels_content = zf.read(name).decode("utf-8", errors="replace")
                # Look for external targets
                if 'TargetMode="External"' in rels_content:
                    external_urls = re.findall(
                        r'Target="(https?://[^"]+)"[^>]*TargetMode="External"',
                        rels_content,
                    )
                    external_refs.extend(external_urls)
            except Exception:
                pass

    structural["has_external_relationships"] = len(external_refs) > 0
    structural["external_relationship_count"] = len(external_refs)
    structural["external_targets"] = external_refs[:20]  # cap

    # --- ActiveX controls ---
    activex = [n for n in names if "activeX" in n.lower()]
    structural["has_activex"] = len(activex) > 0
    structural["activex_count"] = len(activex)

    # --- Content type analysis ---
    if "[Content_Types].xml" in names:
        try:
            ct = zf.read("[Content_Types].xml").decode("utf-8", errors="replace")
            structural["content_types_count"] = ct.count("<Override") + ct.count("<Default")
        except Exception:
            pass

    # --- Part count (complexity indicator) ---
    structural["total_parts"] = len(names)

    # --- Entropy ---
    try:
        with open(file_path, "rb") as f:
            structural["entropy"] = _calculate_entropy(f.read())
    except Exception:
        pass

    return structural


def _extract_office_urls(zf: zipfile.ZipFile) -> list[str]:
    """Extract URLs from Office document content and relationships."""
    urls = set()

    for name in zf.namelist():
        if not (name.endswith(".xml") or name.endswith(".rels")):
            continue

        try:
            content = zf.read(name).decode("utf-8", errors="replace")
            found = URL_PATTERN.findall(content)
            urls.update(found)
        except Exception:
            continue

    # Filter out standard Microsoft/Office schema URLs
    filtered = [
        u for u in urls
        if not any(domain in u for domain in [
            "schemas.openxmlformats.org",
            "schemas.microsoft.com",
            "purl.org/dc",
            "www.w3.org",
            "ns.adobe.com",
        ])
    ]

    return filtered[:100]


def _calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy."""
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
        "macro_files": [],
        "has_embedded_objects": False,
        "embedded_object_count": 0,
        "has_external_relationships": False,
        "external_relationship_count": 0,
        "external_targets": [],
        "has_activex": False,
        "activex_count": 0,
        "has_urls": False,
        "url_count": 0,
        "entropy": 0.0,
        "total_parts": 0,
        "content_types_count": 0,
    }
