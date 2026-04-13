"""
Analysis pipeline endpoints.

All routes prefixed with /api/v1/analysis/ (see core/urls.py).

Endpoint map:
  POST  upload/                    → upload & validate file, start analysis
  GET   reports/                   → list reports (analyst: own, admin: all)
  GET   reports/<id>/              → single report with full evidence
  GET   reports/<id>/export/       → export report as PDF or JSON
"""

from django.urls import path

from .views import (
    FileUploadView,
    ReportListView,
    ReportDetailView,
    ReportExportView,
)

urlpatterns = [
    # File upload
    path("upload/", FileUploadView.as_view(), name="file-upload"),

    # Reports
    path("reports/", ReportListView.as_view(), name="report-list"),
    path("reports/<uuid:id>/", ReportDetailView.as_view(), name="report-detail"),
    path("reports/<uuid:id>/export/", ReportExportView.as_view(), name="report-export"),
]
