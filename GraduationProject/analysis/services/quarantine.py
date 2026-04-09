"""
Quarantine storage service.

Saves validated uploads to the quarantine directory with a UUID-based
filename to prevent path traversal and name collisions.

Files in quarantine:
  - Are never executed (static analysis only)
  - Are stored with restricted read paths
  - Are deleted after DATA_RETENTION_DAYS

This maps to the "Object Storage (Quarantine)" in the data flow diagram.
"""

import logging
import uuid
from pathlib import Path

from django.conf import settings

logger = logging.getLogger("analysis")


def save_to_quarantine(uploaded_file, sha256: str, original_extension: str) -> str:
    """
    Save an uploaded file to the quarantine directory.

    Uses a UUID-based filename (not the original name) to prevent:
      - Path traversal attacks
      - Filename collisions
      - Information leakage from original names

    Args:
        uploaded_file: Django UploadedFile object
        sha256: Pre-computed SHA-256 hash
        original_extension: e.g. ".pdf", ".docx"

    Returns:
        Relative path within QUARANTINE_DIR (e.g. "ab/cd/abcd1234...uuid.pdf")
    """
    quarantine_dir = Path(settings.QUARANTINE_DIR)

    # Create subdirectory structure based on first 4 chars of SHA-256
    # This prevents too many files in a single directory
    sub_dir = quarantine_dir / sha256[:2] / sha256[2:4]
    sub_dir.mkdir(parents=True, exist_ok=True)

    # UUID filename — no relation to original filename
    safe_name = f"{uuid.uuid4().hex}{original_extension}"
    file_path = sub_dir / safe_name

    # Write file in chunks (memory-safe for large files)
    uploaded_file.seek(0)
    with open(file_path, "wb") as dest:
        for chunk in uploaded_file.chunks(chunk_size=8192):
            dest.write(chunk)

    # Return the relative path from QUARANTINE_DIR
    relative_path = str(file_path.relative_to(quarantine_dir))

    logger.info(
        "File saved to quarantine: %s (sha256=%s)",
        relative_path, sha256[:12],
    )

    return relative_path


def get_quarantine_full_path(relative_path: str) -> Path:
    """
    Get the full filesystem path for a quarantined file.

    Used by the analysis worker to read the file for processing.
    """
    return Path(settings.QUARANTINE_DIR) / relative_path


def delete_from_quarantine(relative_path: str) -> bool:
    """
    Delete a file from quarantine (used by retention cleanup).

    Returns True if deleted, False if file was not found.
    """
    full_path = get_quarantine_full_path(relative_path)
    try:
        if full_path.exists():
            full_path.unlink()
            logger.info("Deleted from quarantine: %s", relative_path)
            return True
        return False
    except OSError as e:
        logger.error("Failed to delete from quarantine: %s — %s", relative_path, e)
        return False
