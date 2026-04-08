"""
Analysis pipeline endpoints.

All routes prefixed with /api/v1/analysis/ (see core/urls.py).
Endpoints will be built in Steps 4–8.
"""

from django.urls import path

urlpatterns = [
    # Step 4:  POST  upload/                → upload & validate file
    # Step 8:  GET   reports/               → list reports (analyst: own, admin: all)
    # Step 8:  GET   reports/<id>/          → single report detail
    # Step 8:  GET   reports/<id>/export/   → export PDF or JSON
]
