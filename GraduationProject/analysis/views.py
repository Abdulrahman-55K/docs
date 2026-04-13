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
        # Try async (Celery) first, fall back to synchronous if unavailable
        task_id = None
        try:
            task = run_analysis.delay(str(file_record.id))
            task_id = task.id
        except Exception as e:
            # Celery/Redis not running — run synchronously
            logger.info("Celery unavailable, running analysis synchronously: %s", e)
            try:
                run_analysis(str(file_record.id))
            except Exception as sync_error:
                logger.error("Synchronous analysis failed: %s", sync_error)

        # Reload file to get updated status
        file_record.refresh_from_db()

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
                "task_id": task_id,
                "sync": task_id is None,
            },
        )

        # ------- Build response -------
        response_data = {
            "message": "File received. Analysis in progress.",
            "file_id": str(file_record.id),
            "status": file_record.status,
            "sha256": sha256,
        }

        # If analysis completed synchronously, include the report ID
        if file_record.status == File.Status.COMPLETED:
            try:
                result = file_record.result
                response_data["message"] = "Analysis complete."
                response_data["report_id"] = str(result.id)
                response_data["banner"] = result.banner
            except Result.DoesNotExist:
                pass

        logger.info(
            "File processed: %s (file_id=%s, status=%s)",
            uploaded_file.name, file_record.id, file_record.status,
        )

        return Response(response_data, status=status.HTTP_202_ACCEPTED)


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


# ---------------------------------------------------------------------------
# GET /api/v1/analysis/reports/<id>/export/?format=pdf|json
# ---------------------------------------------------------------------------
class ReportExportView(APIView):
    """
    Export a report as PDF or JSON download.

    Query params:
      format=pdf  → downloadable PDF file
      format=json → downloadable JSON file (default)

    Matches report Section 3.2.1.1.10 "export options to PDF and JSON"
    """

    permission_classes = [IsAuthenticated, IsAnalystOrAdmin]

    def get(self, request, id):
        # Get the result with RBAC
        try:
            queryset = Result.objects.select_related("file", "cluster")
            if request.user.role == "analyst":
                queryset = queryset.filter(file__uploaded_by=request.user)
            result = queryset.get(id=id)
        except Result.DoesNotExist:
            return Response(
                {"error": "Report not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        export_format = request.query_params.get("format", "json").lower()

        from .services.report_export import export_as_json, export_as_pdf
        from django.http import HttpResponse

        if export_format == "pdf":
            pdf_bytes = export_as_pdf(result)
            if pdf_bytes is None:
                return Response(
                    {"error": "PDF export unavailable. reportlab may not be installed."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

            filename = f"report_{result.file.sha256[:12]}.pdf"
            response = HttpResponse(pdf_bytes, content_type="application/pdf")
            response["Content-Disposition"] = f'attachment; filename="{filename}"'

            log_audit(
                request=request,
                category="analysis",
                action="Report exported (PDF)",
                details={"report_id": str(result.id), "sha256": result.file.sha256},
            )
            return response

        else:
            # JSON export
            json_data = export_as_json(result)
            filename = f"report_{result.file.sha256[:12]}.json"

            from django.http import JsonResponse
            response = JsonResponse(json_data, json_dumps_params={"indent": 2})
            response["Content-Disposition"] = f'attachment; filename="{filename}"'

            log_audit(
                request=request,
                category="analysis",
                action="Report exported (JSON)",
                details={"report_id": str(result.id), "sha256": result.file.sha256},
            )
            return response
