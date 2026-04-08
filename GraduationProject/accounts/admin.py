from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, OTP


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ("email", "role", "is_verified", "is_active", "created_at")
    list_filter = ("role", "is_verified", "is_active")
    search_fields = ("email",)
    ordering = ("-created_at",)

    # Override fieldsets since we removed username
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Role & Status", {"fields": ("role", "is_verified", "is_active", "is_staff")}),
        ("Dates", {"fields": ("last_login", "created_at")}),
    )
    readonly_fields = ("created_at",)
    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("email", "password1", "password2", "role"),
        }),
    )


@admin.register(OTP)
class OTPAdmin(admin.ModelAdmin):
    list_display = ("user", "purpose", "is_used", "created_at", "expires_at")
    list_filter = ("purpose", "is_used")
    readonly_fields = ("code",)
