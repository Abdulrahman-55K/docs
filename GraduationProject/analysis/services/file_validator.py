"""
File validation service.

Performs multi-layer validation before a file enters quarantine:
  1. Extension check — must be .pdf, .docx, .xlsx, or .pptx
  2. MIME type check — Content-Type must match allowed types
  3. Magic bytes check — first bytes of file must match expected signatures
  4. Size check — must not exceed MAX_UPLOAD_SIZE_BYTES
  5. SHA-256 hash — computed for idempotency and VT lookups

This maps to the "Ingest Service — Validate" box in the data flow diagram
and Section 3.2.1.1.4 "Upload & Validate File" in the project report.
"""

import hashlib
import logging
from pathlib import Path

from django.conf import settings

logger = logging.getLogger("analysis")

# -------------------------------------------------------------------------
# Magic bytes signatures for each allowed file type
# PDF:  starts with %PDF
# DOCX/XLSX/PPTX: ZIP archives starting with PK (0x504B)
# -------------------------------------------------------------------------
MAGIC_SIGNATURES = {
    "application/pdf": [
        b"%PDF",
    ],
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": [
        b"PK\x03\x04",
        b"PK\x05\x06",
        b"PK\x07\x08",
    ],
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": [
        b"PK\x03\x04",
        b"PK\x05\x06",
        b"PK\x07\x08",
    ],
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": [
        b"PK\x03\x04",
        b"PK\x05\x06",
        b"PK\x07\x08",
    ],
}

# Map extensions to expected MIME types
EXTENSION_TO_MIME = {
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}


def validate_file_extension(filename: str) -> tuple[bool, str]:
    """
    Check that the file extension is one of the allowed types.

    Returns (True, mime_type) or (False, error_message).
    """
    ext = Path(filename).suffix.lower()
    if ext not in EXTENSION_TO_MIME:
        allowed = ", ".join(EXTENSION_TO_MIME.keys())
        return False, f"File type '{ext}' is not allowed. Accepted types: {allowed}"
    return True, EXTENSION_TO_MIME[ext]


def validate_file_size(file_size: int) -> tuple[bool, str]:
    """
    Check that the file does not exceed the configured size limit.

    Returns (True, "") or (False, error_message).
    """
    max_size = settings.MAX_UPLOAD_SIZE_BYTES
    if file_size > max_size:
        max_mb = settings.MAX_UPLOAD_SIZE_MB
        actual_mb = round(file_size / (1024 * 1024), 1)
        return False, f"File size ({actual_mb} MB) exceeds the {max_mb} MB limit."
    return True, ""


def validate_mime_type(content_type: str, expected_mime: str) -> tuple[bool, str]:
    """
    Check that the uploaded file's Content-Type matches the expected MIME
    based on its extension.

    Returns (True, "") or (False, error_message).
    """
    if content_type != expected_mime:
        return False, (
            f"MIME type mismatch: file extension expects '{expected_mime}' "
            f"but got '{content_type}'."
        )
    return True, ""


def validate_magic_bytes(file_header: bytes, expected_mime: str) -> tuple[bool, str]:
    """
    Check the file's magic bytes (first few bytes) against known signatures.

    This prevents attacks where an attacker renames a .exe to .pdf.
    Returns (True, "") or (False, error_message).
    """
    signatures = MAGIC_SIGNATURES.get(expected_mime, [])
    if not signatures:
        return False, f"No known signature for MIME type '{expected_mime}'."

    for sig in signatures:
        if file_header[: len(sig)] == sig:
            return True, ""

    return False, (
        "File content does not match its extension. "
        "The file may be corrupted or disguised."
    )


def compute_sha256(uploaded_file) -> str:
    """
    Compute SHA-256 hash of the uploaded file.

    Reads in chunks to handle large files without loading
    the entire file into memory.
    """
    sha256 = hashlib.sha256()
    uploaded_file.seek(0)
    for chunk in uploaded_file.chunks(chunk_size=8192):
        sha256.update(chunk)
    uploaded_file.seek(0)  # reset for later use
    return sha256.hexdigest()


def validate_uploaded_file(uploaded_file) -> dict:
    """
    Run all validation checks on an uploaded file.

    Returns a dict:
      On success: {"valid": True, "sha256": "...", "mime": "...", "size": ...}
      On failure: {"valid": False, "error": "..."}
    """
    filename = uploaded_file.name
    file_size = uploaded_file.size
    content_type = uploaded_file.content_type

    # 1. Extension check
    ok, result = validate_file_extension(filename)
    if not ok:
        logger.warning("Upload rejected (extension): %s — %s", filename, result)
        return {"valid": False, "error": result}

    expected_mime = result

    # 2. Size check
    ok, error = validate_file_size(file_size)
    if not ok:
        logger.warning("Upload rejected (size): %s — %s", filename, error)
        return {"valid": False, "error": error}

    # 3. MIME type check
    ok, error = validate_mime_type(content_type, expected_mime)
    if not ok:
        logger.warning("Upload rejected (MIME): %s — %s", filename, error)
        return {"valid": False, "error": error}

    # 4. Magic bytes check (read first 8 bytes)
    file_header = uploaded_file.read(8)
    uploaded_file.seek(0)

    if len(file_header) < 4:
        return {"valid": False, "error": "File is too small to be a valid document."}

    ok, error = validate_magic_bytes(file_header, expected_mime)
    if not ok:
        logger.warning("Upload rejected (magic bytes): %s — %s", filename, error)
        return {"valid": False, "error": error}

    # 5. Compute SHA-256
    sha256 = compute_sha256(uploaded_file)

    logger.info(
        "Upload validated: %s (mime=%s, size=%d, sha256=%s)",
        filename, expected_mime, file_size, sha256[:12],
    )

    return {
        "valid": True,
        "sha256": sha256,
        "mime": expected_mime,
        "size": file_size,
    }
