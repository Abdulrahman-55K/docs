"""
Admin panel serializers.

  - DashboardSerializer       → aggregated metrics
  - AuditLogSerializer        → audit log entries
  - YaraRuleSetSerializer     → YARA rule management
  - MLModelVersionSerializer  → ML model management
  - APIKeyConfigSerializer    → API key management
"""

from rest_framework import serializers
from .models import AuditLog, YaraRuleSet, MLModelVersion, APIKeyConfig


class DashboardMetricsSerializer(serializers.Serializer):
    """Read-only dashboard metrics for the admin overview."""

    today_scans = serializers.IntegerField()
    total_scans = serializers.IntegerField()
    total_users = serializers.IntegerField()
    status_breakdown = serializers.DictField()
    errors_today = serializers.IntegerField()
    ml_success_rate = serializers.FloatField()
    ml_fallback_rate = serializers.FloatField()
    vt_success_rate = serializers.FloatField()
    recent_reports = serializers.ListField()


class AuditLogSerializer(serializers.ModelSerializer):
    """Audit log entry for the admin activity log page."""

    user_email = serializers.SerializerMethodField()
    user_role = serializers.SerializerMethodField()

    class Meta:
        model = AuditLog
        fields = [
            "id", "user_email", "user_role", "category",
            "action", "ip_address", "details_json", "occurred_at",
        ]
        read_only_fields = fields

    def get_user_email(self, obj):
        return obj.user.email if obj.user else "system"

    def get_user_role(self, obj):
        return obj.user.role if obj.user else "system"


class YaraRuleSetSerializer(serializers.ModelSerializer):
    """YARA rule set for admin management."""

    uploaded_by_email = serializers.SerializerMethodField()

    class Meta:
        model = YaraRuleSet
        fields = [
            "id", "name", "version", "description", "rule_file",
            "status", "uploaded_by_email", "created_at", "updated_at",
        ]
        read_only_fields = ["id", "uploaded_by_email", "created_at", "updated_at"]

    def get_uploaded_by_email(self, obj):
        return obj.uploaded_by.email if obj.uploaded_by else None


class YaraRuleSetCreateSerializer(serializers.ModelSerializer):
    """Create/upload a new YARA rule set."""

    class Meta:
        model = YaraRuleSet
        fields = ["name", "version", "description", "rule_file", "status"]

    def validate_rule_file(self, value):
        if not value.name.endswith((".yar", ".yara")):
            raise serializers.ValidationError(
                "YARA rule file must have .yar or .yara extension."
            )
        return value


class MLModelVersionSerializer(serializers.ModelSerializer):
    """ML model version for admin management."""

    uploaded_by_email = serializers.SerializerMethodField()

    class Meta:
        model = MLModelVersion
        fields = [
            "id", "version", "description", "model_file",
            "is_active", "uploaded_by_email", "created_at",
        ]
        read_only_fields = ["id", "uploaded_by_email", "created_at"]

    def get_uploaded_by_email(self, obj):
        return obj.uploaded_by.email if obj.uploaded_by else None


class MLModelVersionCreateSerializer(serializers.ModelSerializer):
    """Upload a new ML model version."""

    class Meta:
        model = MLModelVersion
        fields = ["version", "description", "model_file"]

    def validate_model_file(self, value):
        valid_extensions = (".pkl", ".joblib", ".h5", ".onnx")
        if not any(value.name.endswith(ext) for ext in valid_extensions):
            raise serializers.ValidationError(
                f"Model file must have one of these extensions: {', '.join(valid_extensions)}"
            )
        return value

    def validate_version(self, value):
        if MLModelVersion.objects.filter(version=value).exists():
            raise serializers.ValidationError(
                f"Model version '{value}' already exists."
            )
        return value


class APIKeyConfigSerializer(serializers.ModelSerializer):
    """API key config — never exposes the actual key."""

    configured_by_email = serializers.SerializerMethodField()
    key_preview = serializers.SerializerMethodField()

    class Meta:
        model = APIKeyConfig
        fields = [
            "id", "service", "status", "key_preview",
            "last_used", "last_rotated", "configured_by_email",
        ]
        read_only_fields = fields

    def get_configured_by_email(self, obj):
        return obj.configured_by.email if obj.configured_by else None

    def get_key_preview(self, obj):
        """Show only first 4 and last 4 characters."""
        key = obj.key_hash
        if key and len(key) > 10:
            return f"{key[:4]}...{key[-4:]}"
        return "****"


class APIKeyConfigCreateSerializer(serializers.Serializer):
    """Add or rotate an API key."""

    service = serializers.CharField(max_length=100)
    api_key = serializers.CharField(write_only=True)
