"""
Administration models.

AUDIT table from ER diagram: id, user_id, action, occurred_at, details_json

Plus YaraRuleSet and SystemConfig for managing YARA rules,
API keys, and ML model versions through the admin UI.
"""

import uuid
from django.conf import settings
from django.db import models


class AuditLog(models.Model):
    """
    Append-only audit log for security-relevant actions.

    ER: AUDIT(id, user_id, action, occurred_at, details_json)

    Covers: logins, uploads, rule/model changes, admin actions,
    password resets, failed auth attempts.
    """

    class Category(models.TextChoices):
        AUTH = "auth", "Authentication"
        UPLOAD = "upload", "File Upload"
        ANALYSIS = "analysis", "Analysis"
        CONFIG = "config", "Configuration Change"
        ADMIN = "admin", "Admin Action"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs",
    )
    category = models.CharField(max_length=20, choices=Category.choices)
    action = models.CharField(max_length=200)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    details_json = models.JSONField(
        default=dict,
        help_text="Extra context: file hash, rule name, error message, etc.",
    )
    occurred_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "audit"
        ordering = ["-occurred_at"]
        # Append-only: no update/delete through normal means
        verbose_name = "audit log entry"
        verbose_name_plural = "audit log entries"

    def __str__(self):
        user_email = self.user.email if self.user else "system"
        return f"[{self.occurred_at:%Y-%m-%d %H:%M}] {user_email}: {self.action}"


class YaraRuleSet(models.Model):
    """
    Versioned YARA rule sets managed by admins.

    Admin can upload .yar files, enable/disable them.
    Workers reload active rules when scanning.
    """

    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        INACTIVE = "inactive", "Inactive"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200, unique=True)
    version = models.CharField(max_length=50, default="1.0")
    description = models.TextField(blank=True, default="")
    rule_file = models.FileField(upload_to="yara_rules/")
    status = models.CharField(
        max_length=10, choices=Status.choices, default=Status.ACTIVE
    )
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="uploaded_rules",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "yara_rule_sets"
        ordering = ["-updated_at"]

    def __str__(self):
        return f"{self.name} v{self.version} ({self.status})"


class MLModelVersion(models.Model):
    """
    Versioned ML models managed by admins.

    Admin uploads a model artifact (.pkl / .joblib).
    The active version is used by the scoring service.
    Rollback is possible by promoting an older version.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    version = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True, default="")
    model_file = models.FileField(upload_to="models/")
    is_active = models.BooleanField(
        default=False,
        help_text="Only one version should be active at a time",
    )
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="uploaded_models",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ml_model_versions"
        ordering = ["-created_at"]

    def __str__(self):
        active = " [ACTIVE]" if self.is_active else ""
        return f"Model v{self.version}{active}"


class APIKeyConfig(models.Model):
    """
    Stores external API key configurations (e.g., VirusTotal).

    Keys are stored encrypted at rest in production.
    The admin UI never displays full key values.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    service = models.CharField(max_length=100, unique=True, help_text="e.g. virustotal")
    key_hash = models.CharField(
        max_length=200,
        help_text="Hashed or encrypted API key (never plaintext in DB)",
    )
    status = models.CharField(max_length=20, default="active")
    last_used = models.DateTimeField(null=True, blank=True)
    last_rotated = models.DateTimeField(auto_now=True)
    configured_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="configured_keys",
    )

    class Meta:
        db_table = "api_key_configs"

    def __str__(self):
        return f"{self.service} ({self.status})"
