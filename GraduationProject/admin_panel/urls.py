"""
Administration panel endpoints — admin role only.

All routes prefixed with /api/v1/admin-panel/ (see core/urls.py).

Endpoint map:
  GET   dashboard/                → aggregated metrics
  GET   audit-logs/               → searchable audit log
  GET   yara-rules/               → list YARA rule sets
  POST  yara-rules/               → upload new rule set
  PATCH yara-rules/<id>/          → enable/disable rule
  DELETE yara-rules/<id>/         → delete rule set
  GET   ml-models/                → list model versions
  POST  ml-models/                → upload new model
  POST  ml-models/<id>/promote/   → set as active
  GET   api-keys/                 → list configured keys
  POST  api-keys/                 → add/rotate key
"""

from django.urls import path

from .views import (
    DashboardView,
    AuditLogListView,
    YaraRuleListCreateView,
    YaraRuleDetailView,
    MLModelListCreateView,
    MLModelPromoteView,
    APIKeyListCreateView,
)

urlpatterns = [
    # Dashboard
    path("dashboard/", DashboardView.as_view(), name="admin-dashboard"),

    # Audit logs
    path("audit-logs/", AuditLogListView.as_view(), name="admin-audit-logs"),

    # YARA rules
    path("yara-rules/", YaraRuleListCreateView.as_view(), name="admin-yara-rules"),
    path("yara-rules/<uuid:id>/", YaraRuleDetailView.as_view(), name="admin-yara-rule-detail"),

    # ML models
    path("ml-models/", MLModelListCreateView.as_view(), name="admin-ml-models"),
    path("ml-models/<uuid:id>/promote/", MLModelPromoteView.as_view(), name="admin-ml-model-promote"),

    # API keys
    path("api-keys/", APIKeyListCreateView.as_view(), name="admin-api-keys"),
]
