"""
Analysis pipeline views.

Endpoints:
  POST /api/v1/analysis/upload/            → upload & validate file
  GET  /api/v1/analysis/reports/           → list reports (filtered by role)
  GET  /api/v1/analysis/reports/<id>/      → single report detail
"""

import logging
from pathlib import Path

from django.db import IntegrityError
from rest_framework import status
from rest_framework.generics import ListAPIView, RetrieveAPIView
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.permissions import IsAnalystOrAdmin, IsAdmin
from admin_panel.utils import log_audit
from .models import File, Result
from .serializers import (
    FileUploadSerializer,
    ReportListSerializer,
    ReportDetailSerializer,
)
from .services.file_validator import validate_uploaded_file
from .services.quarantine import save_to_quarantine
from .tasks import run_analysis

logger = logging.getLogger("analysis")


# ---------------------------------------------------------------------------
# POST /api/v1/analysis/upload/
# ---------------------------------------------------------------------------
class FileUploadView(APIView):
    """
    Upload a document for analysis.

    This is the "Ingest Service" from the data flow diagram:
      1. Validate (extension + MIME + magic bytes + size)
      2. Compute SHA-256 hash
      3. Check for duplicate (same hash = return existing result)
      4. Save to quarantine storage
      5. Create File record in database
      6. Enqueue analysis job (Celery)

    Request: multipart/form-data with a "file" field
    Response: 202 Accepted with file_id and analysis_id

    Matches report Section 3.2.1.1.4 "Upload & Validate File"
    """

    permission_classes = [IsAuthenticated, IsAnalystOrAdmin]
    parser_classes = [MultiPartParser]

    def post(self, request):
        serializer = FileUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        uploaded_file = serializer.validated_data["file"]

        # ------- Validation (extension, MIME, magic bytes, size) -------
        validation = validate_uploaded_file(uploaded_file)

        if not validation["valid"]:
            log_audit(
                request=request,
                category="upload",
                action="File upload rejected",
                details={
                    "filename": uploaded_file.name,
                    "reason": validation["error"],
                },
            )
            return Response(
                {"error": validation["error"]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        sha256 = validation["sha256"]
        mime = validation["mime"]
        file_size = validation["size"]

        # ------- Duplicate check (idempotent by SHA-256) -------
        existing = File.objects.filter(
            sha256=sha256, uploaded_by=request.user
        ).first()

        if existing and existing.status == File.Status.COMPLETED:
            # Same file already analyzed — return existing result
            logger.info("Duplicate upload: %s (sha256=%s)", uploaded_file.name, sha256[:12])
            try:
                result = existing.result
                return Response(
                    {
                        "message": "This file has already been analyzed.",
                        "file_id": str(existing.id),
                        "report_id": str(result.id),
                        "status": existing.status,
                        "is_duplicate": True,
                    },
                    status=status.HTTP_200_OK,
                )
            except Result.DoesNotExist:
                pass  # result was deleted, re-analyze

        # ------- Save to quarantine -------
        extension = Path(uploaded_file.name).suffix.lower()
        quarantine_path = save_to_quarantine(uploaded_file, sha256, extension)

        # ------- Create File record -------
        file_record = File.objects.create(
            sha256=sha256,
            original_name=uploaded_file.name,
            mime=mime,
            file_size=file_size,
            status=File.Status.QUEUED,
            quarantine_path=quarantine_path,
            uploaded_by=request.user,
        )

        # ------- Enqueue analysis job -------
        task = run_analysis.delay(str(file_record.id))

        # ------- Audit log -------
        log_audit(
            request=request,
            category="upload",
            action="File uploaded for analysis",
            details={
                "filename": uploaded_file.name,
                "file_id": str(file_record.id),
                "sha256": sha256,
                "mime": mime,
                "size": file_size,
                "task_id": task.id if task else None,
            },
        )

        logger.info(
            "File queued for analysis: %s (file_id=%s, task_id=%s)",
            uploaded_file.name, file_record.id, task.id if task else "sync",
        )

        return Response(
            {
                "message": "File received. Analysis in progress.",
                "file_id": str(file_record.id),
                "status": file_record.status,
                "sha256": sha256,
            },
            status=status.HTTP_202_ACCEPTED,
        )


# ---------------------------------------------------------------------------
# GET /api/v1/analysis/reports/
# ---------------------------------------------------------------------------
class ReportListView(ListAPIView):
    """
    List analysis reports.

    - Analysts see only their own reports
    - Admins see all reports

    Supports filtering by: banner, date range, hash, filename
    Matches report Section 3.2.1.1.10 and Tables 3.7/3.9
    """

    permission_classes = [IsAuthenticated, IsAnalystOrAdmin]
    serializer_class = ReportListSerializer

    def get_queryset(self):
        user = self.request.user
        queryset = Result.objects.select_related("file").all()

        # RBAC: analysts see only their own reports
        if user.role == "analyst":
            queryset = queryset.filter(file__uploaded_by=user)

        # --- Filters ---
        params = self.request.query_params

        # Filter by banner/status
        banner = params.get("status")
        if banner and banner in ["clean", "suspicious", "malicious", "needs_review"]:
            queryset = queryset.filter(banner=banner)

        # Filter by SHA-256 hash
        sha256 = params.get("hash")
        if sha256:
            queryset = queryset.filter(file__sha256__icontains=sha256)

        # Filter by filename
        filename = params.get("filename")
        if filename:
            queryset = queryset.filter(file__original_name__icontains=filename)

        # Filter by date range
        date_from = params.get("date_from")
        if date_from:
            queryset = queryset.filter(created_at__date__gte=date_from)

        date_to = params.get("date_to")
        if date_to:
            queryset = queryset.filter(created_at__date__lte=date_to)

        return queryset.order_by("-created_at")


# ---------------------------------------------------------------------------
# GET /api/v1/analysis/reports/<id>/
# ---------------------------------------------------------------------------
class ReportDetailView(RetrieveAPIView):
    """
    Get full report detail with all evidence.

    Returns: file info, YARA matches, VT summary, ML score/label,
    cluster info, and top contributing features.

    - Analysts can only view their own reports
    - Admins can view any report

    Matches report Section 3.2.1.1.10 and Table 3.6
    """

    permission_classes = [IsAuthenticated, IsAnalystOrAdmin]
    serializer_class = ReportDetailSerializer
    lookup_field = "id"

    def get_queryset(self):
        user = self.request.user
        queryset = Result.objects.select_related("file", "cluster").all()

        # RBAC: analysts see only their own
        if user.role == "analyst":
            queryset = queryset.filter(file__uploaded_by=user)

        return queryset
