"""
Campaign clustering service.

Groups files that share XMP identifiers into clusters,
revealing hidden malware campaigns that reuse lure images
or document templates.

Logic:
  1. Extract XMP IDs from the file's features (DocumentID, InstanceID)
  2. Search existing clusters for matching XMP IDs
  3. If match found → add file to existing cluster
  4. If no match → create new cluster (only for malicious/suspicious files)

Only files labeled malicious or suspicious are clustered,
as stated in Section 3.2.1.1.9 of the report:
  "Precondition: file labeled as malicious from detection pipeline"

This maps to "Campaign Clustering" in the data flow diagram.
"""

import logging
from django.utils import timezone

logger = logging.getLogger("analysis")


def assign_cluster(file_record, features: dict, ml_result: dict):
    """
    Assign a file to a campaign cluster based on XMP identifiers.

    Args:
        file_record: analysis.models.File instance
        features: output from metadata extraction
        ml_result: output from ML scoring

    Returns:
        Cluster instance or None
    """
    from analysis.models import Cluster, Result

    label = ml_result.get("label", "")

    # Only cluster suspicious or malicious files
    if label not in ("suspicious", "malicious"):
        logger.info(
            "Skipping clustering for %s (label=%s — only suspicious/malicious are clustered)",
            file_record.id, label,
        )
        return None

    # Extract all XMP identifiers from the file
    xmp_ids = _collect_xmp_ids(features)

    if not xmp_ids:
        logger.info("No XMP identifiers found for clustering: %s", file_record.id)
        return None

    # Search for existing clusters with matching XMP IDs
    matching_cluster = _find_matching_cluster(xmp_ids)

    if matching_cluster:
        # Update cluster's last_seen timestamp
        matching_cluster.last_seen = timezone.now()
        matching_cluster.save(update_fields=["last_seen"])

        logger.info(
            "File %s joined existing cluster '%s' (size=%d)",
            file_record.id, matching_cluster.name, matching_cluster.size + 1,
        )
        return matching_cluster

    # No match — create new cluster
    new_cluster = _create_cluster(file_record, xmp_ids)
    logger.info(
        "New cluster created for %s: '%s'",
        file_record.id, new_cluster.name,
    )
    return new_cluster


def _collect_xmp_ids(features: dict) -> list[str]:
    """
    Collect all XMP identifiers from extracted features.

    Gathers IDs from:
      - Document-level XMP (DocumentID, InstanceID, OriginalDocumentID)
      - Embedded image XMP IDs (the key Smith research insight)
    """
    xmp = features.get("xmp", {})
    ids = []

    # Document-level XMP IDs
    for field in ["document_id", "instance_id", "original_document_id"]:
        value = xmp.get(field, "")
        if value and value.strip():
            ids.append(value.strip())

    # Image-level XMP IDs (from embedded images in Office docs)
    image_xmp_ids = xmp.get("image_xmp_ids", [])
    for img_entry in image_xmp_ids:
        value = img_entry.get("value", "")
        if value and value.strip():
            ids.append(value.strip())

    # Deduplicate while preserving order
    seen = set()
    unique_ids = []
    for xid in ids:
        if xid not in seen:
            seen.add(xid)
            unique_ids.append(xid)

    return unique_ids


def _find_matching_cluster(xmp_ids: list[str]):
    """
    Search existing clusters for matching XMP identifiers.

    Checks the features (data_json) of files already in clusters
    for any shared XMP IDs.
    """
    from analysis.models import Cluster, Feature, Result

    for xmp_id in xmp_ids:
        # Search features that contain this XMP ID
        matching_features = Feature.objects.filter(
            data_json__xmp__document_id=xmp_id,
        ).exclude(
            file__result__cluster__isnull=True,
        ).select_related("file__result__cluster").first()

        if matching_features and matching_features.file.result.cluster:
            return matching_features.file.result.cluster

        # Also check instance_id
        matching_features = Feature.objects.filter(
            data_json__xmp__instance_id=xmp_id,
        ).exclude(
            file__result__cluster__isnull=True,
        ).select_related("file__result__cluster").first()

        if matching_features and matching_features.file.result.cluster:
            return matching_features.file.result.cluster

        # Check original_document_id
        matching_features = Feature.objects.filter(
            data_json__xmp__original_document_id=xmp_id,
        ).exclude(
            file__result__cluster__isnull=True,
        ).select_related("file__result__cluster").first()

        if matching_features and matching_features.file.result.cluster:
            return matching_features.file.result.cluster

        # Check image XMP IDs (JSON array contains)
        matching_features = Feature.objects.filter(
            data_json__xmp__image_xmp_ids__contains=[{"value": xmp_id}],
        ).exclude(
            file__result__cluster__isnull=True,
        ).select_related("file__result__cluster").first()

        if matching_features and matching_features.file.result.cluster:
            return matching_features.file.result.cluster

    return None


def _create_cluster(file_record, xmp_ids: list[str]):
    """
    Create a new campaign cluster.

    Names the cluster using the first XMP ID (truncated) for readability.
    """
    from analysis.models import Cluster

    # Generate a readable cluster name
    primary_id = xmp_ids[0] if xmp_ids else "unknown"

    # Truncate long XMP IDs for the name
    if len(primary_id) > 20:
        short_id = primary_id[:8] + "..." + primary_id[-8:]
    else:
        short_id = primary_id

    cluster = Cluster.objects.create(
        name=f"Campaign-XMP-{short_id}",
        repr_sha256=file_record.sha256,
    )

    return cluster
