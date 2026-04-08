from django.contrib import admin
from .models import File, Feature, YaraHit, Cluster, Result


@admin.register(File)
class FileAdmin(admin.ModelAdmin):
    list_display = ("original_name", "sha256_short", "mime", "status", "uploaded_by", "created_at")
    list_filter = ("status", "mime")
    search_fields = ("original_name", "sha256")
    readonly_fields = ("id", "sha256", "quarantine_path", "created_at")

    def sha256_short(self, obj):
        return obj.sha256[:12] + "..." if obj.sha256 else ""
    sha256_short.short_description = "SHA-256"


@admin.register(Feature)
class FeatureAdmin(admin.ModelAdmin):
    list_display = ("file", "created_at")
    readonly_fields = ("id", "data_json", "created_at")


@admin.register(YaraHit)
class YaraHitAdmin(admin.ModelAdmin):
    list_display = ("rule_name", "file", "created_at")
    list_filter = ("rule_name",)
    search_fields = ("rule_name", "file__original_name")


@admin.register(Cluster)
class ClusterAdmin(admin.ModelAdmin):
    list_display = ("name", "size", "first_seen", "last_seen")
    readonly_fields = ("id",)


@admin.register(Result)
class ResultAdmin(admin.ModelAdmin):
    list_display = ("file", "banner", "ml_label", "ml_score", "cluster", "created_at")
    list_filter = ("banner", "ml_label")
    search_fields = ("file__original_name", "file__sha256")
