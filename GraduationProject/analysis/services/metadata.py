"""
Metadata extraction router.

Routes extraction to the appropriate handler based on file type:
  - PDF  → pdf_extractor
  - DOCX/XLSX/PPTX → office_extractor

This is the service called by the analysis worker (tasks.py).
"""

import logging
from pathlib import Path

from django.conf import settings

from .pdf_extractor import extract_pdf_metadata
from .office_extractor import extract_office_metadata
from .quarantine import get_quarantine_full_path

logger = logging.getLogger("analysis")


def extract_metadata(file_record) -> dict:
    """
    Extract metadata from a file based on its MIME type.

    Args:
        file_record: analysis.models.File instance

    Returns:
        Dict with keys: xmp, metadata, structural, urls, extraction_status
    """
    file_path = str(get_quarantine_full_path(file_record.quarantine_path))
    mime = file_record.mime

    if not Path(file_path).exists():
        logger.error("Quarantine file not found: %s", file_path)
        return {
            "xmp": {},
            "metadata": {},
            "structural": {},
            "urls": [],
            "extraction_status": "failed: file not found in quarantine",
        }

    logger.info(
        "Extracting metadata: %s (mime=%s, path=%s)",
        file_record.original_name, mime, file_record.quarantine_path,
    )

    if mime == "application/pdf":
        result = extract_pdf_metadata(file_path)
    elif mime in (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ):
        result = extract_office_metadata(file_path)
    else:
        logger.warning("Unsupported MIME type for extraction: %s", mime)
        result = {
            "xmp": {},
            "metadata": {},
            "structural": {},
            "urls": [],
            "extraction_status": f"unsupported mime type: {mime}",
        }

    # Add common fields
    result["file_type"] = mime
    result["file_name"] = file_record.original_name
    result["sha256"] = file_record.sha256

    return result
