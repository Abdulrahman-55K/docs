from django.contrib import admin
from .models import AuditLog, YaraRuleSet, MLModelVersion, APIKeyConfig


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("user", "category", "action", "ip_address", "occurred_at")
    list_filter = ("category",)
    search_fields = ("action", "user__email")
    readonly_fields = ("id", "user", "category", "action", "ip_address", "details_json", "occurred_at")

    def has_add_permission(self, request):
        return False  # append-only

    def has_change_permission(self, request, obj=None):
        return False  # append-only

    def has_delete_permission(self, request, obj=None):
        return False  # append-only


@admin.register(YaraRuleSet)
class YaraRuleSetAdmin(admin.ModelAdmin):
    list_display = ("name", "version", "status", "uploaded_by", "updated_at")
    list_filter = ("status",)


@admin.register(MLModelVersion)
class MLModelVersionAdmin(admin.ModelAdmin):
    list_display = ("version", "is_active", "uploaded_by", "created_at")
    list_filter = ("is_active",)


@admin.register(APIKeyConfig)
class APIKeyConfigAdmin(admin.ModelAdmin):
    list_display = ("service", "status", "last_used", "last_rotated")
    readonly_fields = ("key_hash",)  # never display raw key
