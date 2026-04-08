"""
Analysis pipeline models.

Maps to the ER diagram tables:
  FILES       — uploaded file metadata + quarantine path
  FEATURES    — extracted metadata/XMP/structural features (JSON)
  YARA_HITS   — matched YARA rules per file
  RESULTS     — final verdict: ML label, score, VT summary, banner
  CLUSTERS    — campaign clusters grouped by XMP IDs
"""

import uuid
from django.conf import settings
from django.db import models


class File(models.Model):
    """
    Represents an uploaded document in quarantine.

    ER: FILES(id, sha256, mime, status, created_at)
    """

    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        PROCESSING = "processing", "Processing"
        COMPLETED = "completed", "Completed"
        FAILED_PARSE = "failed_parse", "Failed — Parse"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    sha256 = models.CharField(max_length=64, db_index=True)
    original_name = models.CharField(max_length=255)
    mime = models.CharField(max_length=100)
    file_size = models.PositiveIntegerField(help_text="Size in bytes")
    status = models.CharField(
        max_length=20, choices=Status.choices, default=Status.QUEUED
    )
    quarantine_path = models.CharField(
        max_length=500,
        help_text="Path inside QUARANTINE_DIR",
    )
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="files",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "files"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.original_name} ({self.status})"


class Feature(models.Model):
    """
    Extracted features for a file — stored as JSON for flexibility.

    ER: FEATURES(id, file_id, data_json)

    data_json contains:
      - XMP fields (DocumentID, InstanceID, etc.)
      - Structural indicators (macro count, embedded objects, URLs)
      - Statistics (entropy, size ratios, page count)
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file = models.OneToOneField(File, on_delete=models.CASCADE, related_name="features")
    data_json = models.JSONField(
        default=dict,
        help_text="All extracted features as a JSON object",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "features"

    def __str__(self):
        return f"Features for {self.file.original_name}"


class YaraHit(models.Model):
    """
    A single YARA rule match against a file.

    ER: YARA_HITS(id, file_id, rule_name, details)
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name="yara_hits")
    rule_name = models.CharField(max_length=200)
    details = models.JSONField(
        default=dict,
        help_text="Match details: tags, byte offsets, severity, description",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "yara_hits"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.rule_name} → {self.file.original_name}"


class Cluster(models.Model):
    """
    Campaign cluster — groups files that share XMP IDs or similar metadata.

    ER: CLUSTERS(id, name, repr_sha256)
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(
        max_length=200,
        help_text="Human-readable cluster label, e.g. 'Campaign-XMP-abc123'",
    )
    repr_sha256 = models.CharField(
        max_length=64,
        blank=True,
        help_text="Representative file hash for this cluster",
    )
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "clusters"
        ordering = ["-last_seen"]

    def __str__(self):
        return self.name

    @property
    def size(self):
        return self.results.count()


class Result(models.Model):
    """
    Final analysis verdict for a file.

    ER: RESULTS(id, file_id, ml_label, ml_score, vt_summary_json, banner)
    """

    class Banner(models.TextChoices):
        CLEAN = "clean", "Clean"
        SUSPICIOUS = "suspicious", "Suspicious"
        MALICIOUS = "malicious", "Malicious"
        NEEDS_REVIEW = "needs_review", "Needs Review"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file = models.OneToOneField(File, on_delete=models.CASCADE, related_name="result")
    ml_label = models.CharField(max_length=30, blank=True, default="")
    ml_score = models.FloatField(default=0.0)
    vt_summary_json = models.JSONField(
        default=dict,
        help_text="VirusTotal enrichment snapshot: detections, first/last seen",
    )
    banner = models.CharField(
        max_length=20, choices=Banner.choices, default=Banner.NEEDS_REVIEW
    )
    top_features = models.JSONField(
        default=list,
        help_text="Top contributing features for explainability",
    )
    cluster = models.ForeignKey(
        Cluster,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="results",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "results"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.file.original_name} → {self.banner}"
