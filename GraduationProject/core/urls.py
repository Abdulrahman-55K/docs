"""
Root URL configuration.

All API endpoints live under /api/v1/ for clean versioning.
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    # Django admin (dev only — disable or protect in production)
    path("admin/", admin.site.urls),

    # === API v1 ===
    path("api/v1/auth/", include("accounts.urls")),
    path("api/v1/analysis/", include("analysis.urls")),
    path("api/v1/admin-panel/", include("admin_panel.urls")),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
