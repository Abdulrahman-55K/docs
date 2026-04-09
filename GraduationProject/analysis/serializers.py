"""
Serializers for the analysis pipeline.

  - FileUploadSerializer    → validates the uploaded file
  - FileSerializer          → read-only file info
  - ReportListSerializer    → summary for reports list
  - ReportDetailSerializer  → full report with all evidence
"""

from rest_framework import serializers
from .models import File, Feature, YaraHit, Result, Cluster


class FileUploadSerializer(serializers.Serializer):
    """
    Validates the file upload request.

    The actual MIME/magic/size validation happens in the view
    using file_validator service — this serializer just ensures
    a file was provided in the request.
    """

    file = serializers.FileField()


class FileSerializer(serializers.ModelSerializer):
    """Read-only file metadata."""

    class Meta:
        model = File
        fields = [
            "id", "sha256", "original_name", "mime",
            "file_size", "status", "created_at",
        ]
        read_only_fields = fields


class YaraHitSerializer(serializers.ModelSerializer):
    """YARA match details for a report."""

    class Meta:
        model = YaraHit
        fields = ["rule_name", "details"]
        read_only_fields = fields


class ClusterSerializer(serializers.ModelSerializer):
    """Campaign cluster info for a report."""

    size = serializers.IntegerField(read_only=True)

    class Meta:
        model = Cluster
        fields = ["id", "name", "repr_sha256", "size", "first_seen", "last_seen"]
        read_only_fields = fields


class ReportListSerializer(serializers.ModelSerializer):
    """
    Summary serializer for the reports list page.

    Matches what the React Reports.tsx page expects:
      id, filename, uploadDate, status, score, yaraMatches, vtDetections
    """

    filename = serializers.CharField(source="file.original_name")
    upload_date = serializers.DateTimeField(source="file.created_at")
    file_hash = serializers.CharField(source="file.sha256")
    status = serializers.CharField(source="banner")
    score = serializers.FloatField(source="ml_score")
    yara_matches = serializers.SerializerMethodField()
    vt_detections = serializers.SerializerMethodField()

    class Meta:
        model = Result
        fields = [
            "id", "filename", "upload_date", "file_hash",
            "status", "score", "yara_matches", "vt_detections",
        ]
        read_only_fields = fields

    def get_yara_matches(self, obj):
        return obj.file.yara_hits.count()

    def get_vt_detections(self, obj):
        vt = obj.vt_summary_json
        if isinstance(vt, dict):
            return vt.get("malicious", 0)
        return 0


class ReportDetailSerializer(serializers.ModelSerializer):
    """
    Full report with all evidence — used by ReportDetail.tsx.

    Includes: file info, YARA matches, VT summary, ML classification,
    cluster info, and top contributing features.
    """

    file = FileSerializer()
    yara_hits = serializers.SerializerMethodField()
    cluster = ClusterSerializer(allow_null=True)

    class Meta:
        model = Result
        fields = [
            "id", "file", "ml_label", "ml_score",
            "vt_summary_json", "banner", "top_features",
            "yara_hits", "cluster", "created_at",
        ]
        read_only_fields = fields

    def get_yara_hits(self, obj):
        hits = obj.file.yara_hits.all()
        return YaraHitSerializer(hits, many=True).data
