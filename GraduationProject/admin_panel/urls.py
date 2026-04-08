"""
Administration endpoints — admin role only.

All routes prefixed with /api/v1/admin-panel/ (see core/urls.py).
Endpoints will be built in Step 9.
"""

from django.urls import path

urlpatterns = [
    # Step 9 will add:
    # GET   dashboard/              → aggregated metrics
    # GET   audit-logs/             → searchable audit log
    # GET   yara-rules/             → list YARA rule sets
    # POST  yara-rules/             → upload new rule set
    # PATCH yara-rules/<id>/        → enable/disable rule
    # GET   ml-models/              → list model versions
    # POST  ml-models/              → upload new model
    # POST  ml-models/<id>/promote/ → set as active
    # GET   api-keys/               → list configured keys
    # POST  api-keys/               → add/rotate key
]
