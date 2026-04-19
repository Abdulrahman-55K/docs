"""
Analysis pipeline views.

Endpoints:
  POST /api/v1/analysis/upload/               → upload & validate file
  GET  /api/v1/analysis/reports/              → list reports (filtered by role)
  GET  /api/v1/analysis/reports/<id>/         → single report detail
  GET  /api/v1/analysis/reports/<id>/export/  → export as PDF or JSON
"""

import logging
from pathlib import Path

from rest_framework import status
from rest_framework.generics import ListAPIView, RetrieveAPIView
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.permissions import IsAnalystOrAdmin
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


class FileUploadView(APIView):
    """Upload a document for analysis."""

    permission_classes = [IsAuthenticated, IsAnalystOrAdmin]
    parser_classes = [MultiPartParser]

    def post(self, request):
        serializer = FileUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        uploaded_file = serializer.validated_data["file"]

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

        existing = File.objects.filter(
            sha256=sha256, uploaded_by=request.user
        ).first()

        if existing and existing.status == File.Status.COMPLETED:
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
                pass

        extension = Path(uploaded_file.name).suffix.lower()
        quarantine_path = save_to_quarantine(uploaded_file, sha256, extension)

        file_record = File.objects.create(
            sha256=sha256,
            original_name=uploaded_file.name,
            mime=mime,
            file_size=file_size,
            status=File.Status.QUEUED,
            quarantine_path=quarantine_path,
            uploaded_by=request.user,
        )

        task_id = None
        try:
            task = run_analysis.delay(str(file_record.id))
            task_id = task.id
        except Exception as e:
            logger.info("Celery unavailable, running analysis synchronously: %s", e)
            try:
                run_analysis(str(file_record.id))
            except Exception as sync_error:
                logger.error("Synchronous analysis failed: %s", sync_error)

        file_record.refresh_from_db()

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

        response_data = {
            "message": "File received. Analysis in progress.",
            "file_id": str(file_record.id),
            "status": file_record.status,
            "sha256": sha256,
        }

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


class ReportListView(ListAPIView):
    """List analysis reports."""

    permission_classes = [IsAuthenticated, IsAnalystOrAdmin]
    serializer_class = ReportListSerializer

    def get_queryset(self):
        user = self.request.user
        queryset = Result.objects.select_related("file").all()

        if user.role == "analyst":
            queryset = queryset.filter(file__uploaded_by=user)

        params = self.request.query_params

        banner = params.get("status")
        if banner and banner in ["clean", "suspicious", "malicious", "needs_review"]:
            queryset = queryset.filter(banner=banner)

        sha256 = params.get("hash")
        if sha256:
            queryset = queryset.filter(file__sha256__icontains=sha256)

        filename = params.get("filename")
        if filename:
            queryset = queryset.filter(file__original_name__icontains=filename)

        date_from = params.get("date_from")
        if date_from:
            queryset = queryset.filter(created_at__date__gte=date_from)

        date_to = params.get("date_to")
        if date_to:
            queryset = queryset.filter(created_at__date__lte=date_to)

        return queryset.order_by("-created_at")


class ReportDetailView(RetrieveAPIView):
    """Get full report detail with all evidence."""

    permission_classes = [IsAuthenticated, IsAnalystOrAdmin]
    serializer_class = ReportDetailSerializer
    lookup_field = "id"

    def get_queryset(self):
        user = self.request.user
        queryset = Result.objects.select_related("file", "cluster").all()

        if user.role == "analyst":
            queryset = queryset.filter(file__uploaded_by=user)

        return queryset


class ReportExportView(APIView):
    """Export a report as PDF or JSON download."""

    permission_classes = [IsAuthenticated, IsAnalystOrAdmin]

    def get(self, request, id):
        logger.info("Export requested: id=%s, user=%s", id, request.user.email)

        try:
            queryset = Result.objects.select_related("file", "cluster")
            if request.user.role == "analyst":
                queryset = queryset.filter(file__uploaded_by=request.user)
            result = queryset.get(id=id)
        except Result.DoesNotExist:
            logger.warning("Export: result not found for id=%s", id)
            return Response(
                {"error": "Report not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        export_format = request.query_params.get("format", "json").lower()
        logger.info("Exporting as %s for report %s", export_format, id)

        from .services.report_export import export_as_json, export_as_pdf

        if export_format == "pdf":
            pdf_bytes = export_as_pdf(result)
            if pdf_bytes is None:
                return Response(
                    {"error": "PDF export unavailable."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

            filename = f"report_{result.file.sha256[:12]}.pdf"
            from django.http import HttpResponse as DjangoResponse
            response = DjangoResponse(pdf_bytes, content_type="application/pdf")
            response["Content-Disposition"] = f'attachment; filename="{filename}"'
            response["Access-Control-Allow-Origin"] = "http://localhost:5173"
            response["Access-Control-Allow-Credentials"] = "true"
            response["Access-Control-Expose-Headers"] = "Content-Disposition"
            return response

        else:
            json_data = export_as_json(result)
            filename = f"report_{result.file.sha256[:12]}.json"
            from django.http import JsonResponse
            response = JsonResponse(json_data, json_dumps_params={"indent": 2})
            response["Content-Disposition"] = f'attachment; filename="{filename}"'
            response["Access-Control-Allow-Origin"] = "http://localhost:5173"
            response["Access-Control-Allow-Credentials"] = "true"
            response["Access-Control-Expose-Headers"] = "Content-Disposition"
            return response
