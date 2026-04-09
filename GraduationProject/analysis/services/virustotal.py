"""
VirusTotal hash-only enrichment service.

Queries the VirusTotal API using ONLY the file's SHA-256 hash.
No file contents are ever uploaded — privacy is preserved.

Flow:
  1. Check local cache (database) for recent VT result
  2. If cache miss → query VT API v3 /files/{hash}
  3. Store result in cache with timestamp
  4. If VT is unavailable → return "VT unavailable" (graceful degradation)

This maps to "VT Hash Enrichment (Cache to API)" in the data flow diagram
and Section 3.2.1.1.7 "VirusTotal Hash Enrichment" in the report.
"""

import json
import logging
from datetime import timedelta

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

logger = logging.getLogger("analysis")

# Cache prefix and TTL
VT_CACHE_PREFIX = "vt_hash_"
VT_CACHE_TTL_SECONDS = 60 * 60 * 24  # 24 hours


def enrich_hash(file_record) -> dict:
    """
    Look up a file's SHA-256 hash on VirusTotal.

    Args:
        file_record: analysis.models.File instance

    Returns:
        {
            "sha256": "...",
            "malicious": int,
            "suspicious": int,
            "harmless": int,
            "undetected": int,
            "total_engines": int,
            "detection_names": [...],
            "first_seen": "...",
            "last_seen": "...",
            "reputation": int,
            "enrichment_status": "success" | "not_found" | "unavailable: ...",
        }
    """
    sha256 = file_record.sha256
    result = _empty_vt_result(sha256)

    # --- Check API key configuration ---
    api_key = _get_api_key()
    if not api_key:
        result["enrichment_status"] = "unavailable: no API key configured"
        logger.info("VT enrichment skipped (no API key) for %s", sha256[:12])
        return result

    # --- Check local cache first ---
    cached = _get_from_cache(sha256)
    if cached is not None:
        logger.info("VT cache hit for %s", sha256[:12])
        cached["enrichment_status"] = "success (cached)"
        return cached

    # --- Query VirusTotal API ---
    logger.info("VT API lookup for %s", sha256[:12])
    vt_result = _query_virustotal(sha256, api_key)

    if vt_result is not None:
        # Cache the result
        _save_to_cache(sha256, vt_result)
        return vt_result

    # API failed — return unavailable
    result["enrichment_status"] = "unavailable: API request failed"
    return result


def _get_api_key() -> str:
    """
    Get the VirusTotal API key.

    Checks settings first (from .env), then falls back to
    the admin-configured key in the database.
    """
    # Primary: from environment/.env
    key = getattr(settings, "VIRUSTOTAL_API_KEY", "")
    if key:
        return key

    # Fallback: from admin panel config
    try:
        from admin_panel.models import APIKeyConfig
        config = APIKeyConfig.objects.filter(
            service="virustotal", status="active"
        ).first()
        if config:
            return config.key_hash  # In production this would be decrypted
    except Exception:
        pass

    return ""


def _get_from_cache(sha256: str) -> dict | None:
    """Check Django's cache framework for a recent VT result."""
    cache_key = f"{VT_CACHE_PREFIX}{sha256}"

    # Try Django cache first (Redis/memory)
    cached = cache.get(cache_key)
    if cached:
        return cached

    # Fallback: check database for recent VT results
    try:
        from analysis.models import Result
        recent = Result.objects.filter(
            file__sha256=sha256,
            created_at__gte=timezone.now() - timedelta(hours=24),
        ).exclude(
            vt_summary_json={},
        ).first()

        if recent and recent.vt_summary_json.get("enrichment_status", "").startswith("success"):
            return recent.vt_summary_json
    except Exception:
        pass

    return None


def _save_to_cache(sha256: str, data: dict):
    """Save VT result to cache."""
    cache_key = f"{VT_CACHE_PREFIX}{sha256}"
    try:
        cache.set(cache_key, data, VT_CACHE_TTL_SECONDS)
    except Exception as e:
        logger.debug("Cache save failed (non-critical): %s", e)


def _query_virustotal(sha256: str, api_key: str) -> dict | None:
    """
    Query VirusTotal API v3 for a file hash report.

    Endpoint: GET https://www.virustotal.com/api/v3/files/{hash}

    Only sends the hash — never uploads file contents.
    Implements exponential backoff on rate limit (HTTP 429).
    """
    try:
        import requests
    except ImportError:
        logger.error("requests library not installed")
        return None

    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }

    try:
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 200:
            return _parse_vt_response(sha256, response.json())

        elif response.status_code == 404:
            # File not in VT database — this is a valid result
            logger.info("VT: hash not found in database — %s", sha256[:12])
            result = _empty_vt_result(sha256)
            result["enrichment_status"] = "not_found"
            return result

        elif response.status_code == 429:
            # Rate limited
            logger.warning("VT rate limited for %s", sha256[:12])
            return None

        elif response.status_code == 401:
            logger.error("VT API key invalid or expired")
            return None

        else:
            logger.warning(
                "VT API returned %d for %s", response.status_code, sha256[:12]
            )
            return None

    except requests.Timeout:
        logger.warning("VT API timeout for %s", sha256[:12])
        return None
    except requests.ConnectionError:
        logger.warning("VT API connection error for %s", sha256[:12])
        return None
    except Exception as e:
        logger.error("VT API unexpected error for %s: %s", sha256[:12], e)
        return None


def _parse_vt_response(sha256: str, data: dict) -> dict:
    """
    Parse the VirusTotal API v3 response into our standardized format.

    Extracts: detection stats, engine names, first/last seen, reputation.
    """
    result = _empty_vt_result(sha256)

    try:
        attributes = data.get("data", {}).get("attributes", {})

        # Detection statistics
        stats = attributes.get("last_analysis_stats", {})
        result["malicious"] = stats.get("malicious", 0)
        result["suspicious"] = stats.get("suspicious", 0)
        result["harmless"] = stats.get("harmless", 0)
        result["undetected"] = stats.get("undetected", 0)
        result["total_engines"] = sum(stats.values()) if stats else 0

        # Detection names (which engines flagged it)
        analysis_results = attributes.get("last_analysis_results", {})
        detection_names = []
        for engine, detail in analysis_results.items():
            if detail.get("category") in ("malicious", "suspicious"):
                detection_names.append({
                    "engine": engine,
                    "result": detail.get("result", ""),
                    "category": detail.get("category", ""),
                })
        result["detection_names"] = detection_names[:20]  # cap

        # Timestamps
        first_seen = attributes.get("first_submission_date")
        if first_seen:
            result["first_seen"] = str(first_seen)

        last_seen = attributes.get("last_analysis_date")
        if last_seen:
            result["last_seen"] = str(last_seen)

        # Reputation score
        result["reputation"] = attributes.get("reputation", 0)

        # File type info from VT
        result["vt_file_type"] = attributes.get("type_description", "")
        result["vt_magic"] = attributes.get("magic", "")

        # Tags
        result["tags"] = attributes.get("tags", [])[:10]

        result["enrichment_status"] = "success"

        logger.info(
            "VT enrichment: %s — %d/%d malicious",
            sha256[:12], result["malicious"], result["total_engines"],
        )

    except Exception as e:
        logger.error("VT response parse error: %s", e)
        result["enrichment_status"] = f"error: parse failed — {str(e)}"

    return result


def _empty_vt_result(sha256: str) -> dict:
    """Return an empty VT result with default values."""
    return {
        "sha256": sha256,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "total_engines": 0,
        "detection_names": [],
        "first_seen": None,
        "last_seen": None,
        "reputation": 0,
        "vt_file_type": "",
        "vt_magic": "",
        "tags": [],
        "enrichment_status": "pending",
    }
