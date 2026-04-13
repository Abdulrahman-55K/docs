"""
Celery tasks for the analysis pipeline.

The main task `run_analysis` orchestrates the full pipeline:
  1. Extract metadata & XMP (Step 5)
  2. Run YARA scan (Step 6)
  3. VirusTotal hash enrichment (Step 6)
  4. ML risk scoring (Step 7)
  5. Campaign clustering (Step 7)
  6. Generate result & report

Each stage has graceful degradation:
  - YARA fails → skip, mark "YARA unavailable"
  - VT fails → skip, mark "VT unavailable"
  - ML fails → fallback to "Needs Review"

This maps to the "Analysis Worker" in the data flow diagram.
"""

import logging

from celery import shared_task
from django.utils import timezone

logger = logging.getLogger("analysis")


@shared_task(
    bind=True,
    max_retries=2,
    default_retry_delay=30,
    name="analysis.run_analysis",
)
def run_analysis(self, file_id: str):
    """
    Main analysis pipeline task.

    Called when a file is uploaded and enqueued.
    Processes the file through all analysis stages and creates a Result.
    """
    from .models import File, Feature, Result

    logger.info("Starting analysis for file_id=%s", file_id)

    try:
        file_record = File.objects.get(id=file_id)
    except File.DoesNotExist:
        logger.error("File not found: %s", file_id)
        return {"status": "error", "reason": "file_not_found"}

    # Mark as processing
    file_record.status = File.Status.PROCESSING
    file_record.save(update_fields=["status"])

    try:
        # ---------------------------------------------------------------
        # Stage 1: Extract metadata & XMP (Step 5 will implement)
        # ---------------------------------------------------------------
        features_data = _extract_metadata(file_record)

        # Save features to database
        Feature.objects.update_or_create(
            file=file_record,
            defaults={"data_json": features_data},
        )

        # ---------------------------------------------------------------
        # Stage 2: YARA scan (Step 6 will implement)
        # ---------------------------------------------------------------
        yara_results = _run_yara_scan(file_record)

        # ---------------------------------------------------------------
        # Stage 3: VirusTotal hash enrichment (Step 6 will implement)
        # ---------------------------------------------------------------
        vt_data = _enrich_virustotal(file_record)

        # ---------------------------------------------------------------
        # Stage 4: ML risk scoring (Step 7 will implement)
        # ---------------------------------------------------------------
        ml_result = _score_ml(file_record, features_data, yara_results, vt_data)

        # ---------------------------------------------------------------
        # Stage 5: Campaign clustering (Step 7 will implement)
        # ---------------------------------------------------------------
        cluster = _assign_cluster(file_record, features_data, ml_result)

        # ---------------------------------------------------------------
        # Stage 6: Generate result
        # ---------------------------------------------------------------
        result, _ = Result.objects.update_or_create(
            file=file_record,
            defaults={
                "ml_label": ml_result.get("label", "needs_review"),
                "ml_score": ml_result.get("score", 0.0),
                "vt_summary_json": vt_data,
                "banner": ml_result.get("banner", Result.Banner.NEEDS_REVIEW),
                "top_features": ml_result.get("top_features", []),
                "cluster": cluster,
            },
        )

        # Mark as completed
        file_record.status = File.Status.COMPLETED
        file_record.save(update_fields=["status"])

        logger.info(
            "Analysis complete: file_id=%s, banner=%s, score=%.2f",
            file_id, result.banner, result.ml_score,
        )

        return {
            "status": "completed",
            "file_id": file_id,
            "result_id": str(result.id),
            "banner": result.banner,
        }

    except Exception as e:
        logger.error("Analysis failed for file_id=%s: %s", file_id, str(e))

        # Mark file as failed
        file_record.status = File.Status.FAILED
        file_record.save(update_fields=["status"])

        # Create a "Needs Review" result so the report page still works
        Result.objects.update_or_create(
            file=file_record,
            defaults={
                "ml_label": "error",
                "ml_score": 0.0,
                "banner": Result.Banner.NEEDS_REVIEW,
                "vt_summary_json": {"error": str(e)},
                "top_features": [{"feature": "analysis_error", "detail": str(e)}],
            },
        )

        # Retry if we have retries left
        if self.request.retries < self.max_retries:
            raise self.retry(exc=e)

        return {"status": "failed", "file_id": file_id, "error": str(e)}


# ---------------------------------------------------------------------------
# Pipeline stage stubs — each returns sensible defaults for now.
# Steps 5-7 will replace these with real implementations.
# ---------------------------------------------------------------------------

def _extract_metadata(file_record) -> dict:
    """
    Stage 1: Extract metadata and XMP identifiers.

    Uses the metadata extraction service which routes to:
      - pdf_extractor for PDF files
      - office_extractor for DOCX/XLSX/PPTX files

    Extracts: XMP IDs, standard metadata, structural features,
    entropy, macros, URLs, embedded objects.
    """
    logger.info("Stage 1 — Metadata extraction for %s", file_record.id)

    from .services.metadata import extract_metadata
    return extract_metadata(file_record)


def _run_yara_scan(file_record) -> dict:
    """
    Stage 2: YARA rule scanning.

    Loads active YARA rules from admin_panel.YaraRuleSet
    and scans the quarantined file. Gracefully degrades if
    yara-python is not installed or no rules are configured.
    """
    logger.info("Stage 2 — YARA scan for %s", file_record.id)

    from .services.yara_scanner import scan_file
    return scan_file(file_record)


def _enrich_virustotal(file_record) -> dict:
    """
    Stage 3: VirusTotal hash-only enrichment.

    Sends ONLY the SHA-256 hash to VT — never uploads file contents.
    Checks cache first, queries API on miss, gracefully degrades
    if VT is unavailable or rate limited.
    """
    logger.info("Stage 3 — VT enrichment for %s", file_record.id)

    from .services.virustotal import enrich_hash
    return enrich_hash(file_record)


def _score_ml(file_record, features: dict, yara: dict, vt: dict) -> dict:
    """
    Stage 4: ML risk scoring.

    Uses trained ML model if available, otherwise falls back
    to rule-based scoring using VT, YARA, and structural signals.
    """
    logger.info("Stage 4 — ML scoring for %s", file_record.id)

    from .services.ml_scorer import score_file
    return score_file(file_record, features, yara, vt)


def _assign_cluster(file_record, features: dict, ml_result: dict):
    """
    Stage 5: Campaign clustering by XMP IDs.

    Groups files sharing XMP identifiers into clusters.
    Only clusters suspicious/malicious files.
    """
    logger.info("Stage 5 — Clustering for %s", file_record.id)

    from .services.clustering import assign_cluster
    return assign_cluster(file_record, features, ml_result)
