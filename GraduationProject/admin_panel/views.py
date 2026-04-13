"""
Administration panel views — admin role only.

Endpoints:
  GET   /api/v1/admin-panel/dashboard/           → aggregated metrics
  GET   /api/v1/admin-panel/audit-logs/           → searchable audit log
  GET   /api/v1/admin-panel/yara-rules/           → list YARA rule sets
  POST  /api/v1/admin-panel/yara-rules/           → upload new rule set
  PATCH /api/v1/admin-panel/yara-rules/<id>/      → enable/disable rule
  DELETE /api/v1/admin-panel/yara-rules/<id>/     → delete rule set
  GET   /api/v1/admin-panel/ml-models/            → list model versions
  POST  /api/v1/admin-panel/ml-models/            → upload new model
  POST  /api/v1/admin-panel/ml-models/<id>/promote/ → set as active
  GET   /api/v1/admin-panel/api-keys/             → list configured keys
  POST  /api/v1/admin-panel/api-keys/             → add/rotate key
"""

import logging
from datetime import timedelta

from django.db.models import Count, Q
from django.utils import timezone
from rest_framework import status
from rest_framework.generics import ListAPIView
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.permissions import IsAdmin
from analysis.models import File, Result
from .models import AuditLog, YaraRuleSet, MLModelVersion, APIKeyConfig
from .serializers import (
    AuditLogSerializer,
    YaraRuleSetSerializer,
    YaraRuleSetCreateSerializer,
    MLModelVersionSerializer,
    MLModelVersionCreateSerializer,
    APIKeyConfigSerializer,
    APIKeyConfigCreateSerializer,
)
from .utils import log_audit

logger = logging.getLogger("admin_panel")


# ---------------------------------------------------------------------------
# GET /api/v1/admin-panel/dashboard/
# ---------------------------------------------------------------------------
class DashboardView(APIView):
    """
    Admin dashboard with aggregated performance metrics.

    Returns: today's scans, total scans, status breakdown,
    error count, ML/VT success rates, recent reports.

    Matches report Table 3.8 "Dashboard" and Figure 3.15.
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        today = timezone.now().date()
        today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)

        # --- Scan counts ---
        total_scans = File.objects.count()
        today_scans = File.objects.filter(created_at__date=today).count()

        # --- Status breakdown ---
        status_breakdown = dict(
            Result.objects.values_list("banner")
            .annotate(count=Count("id"))
            .values_list("banner", "count")
        )

        # --- Errors today ---
        errors_today = File.objects.filter(
            created_at__date=today,
            status__in=["failed", "failed_parse"],
        ).count()

        # --- ML success rate ---
        total_results = Result.objects.count()
        if total_results > 0:
            ml_model_count = Result.objects.exclude(
                top_features__contains=[{"feature": "no_indicators"}]
            ).filter(
                ml_label__in=["clean", "suspicious", "malicious"],
            ).count()
            ml_fallback = Result.objects.filter(
                ml_label="needs_review",
            ).count()
            ml_success_rate = round(
                (total_results - ml_fallback) / total_results * 100, 1
            )
            ml_fallback_rate = round(ml_fallback / total_results * 100, 1)
        else:
            ml_success_rate = 0.0
            ml_fallback_rate = 0.0

        # --- VT success rate ---
        if total_results > 0:
            vt_success = Result.objects.filter(
                vt_summary_json__enrichment_status__startswith="success",
            ).count()
            vt_not_found = Result.objects.filter(
                vt_summary_json__enrichment_status="not_found",
            ).count()
            vt_success_rate = round(
                (vt_success + vt_not_found) / total_results * 100, 1
            )
        else:
            vt_success_rate = 0.0

        # --- Total users ---
        from accounts.models import User
        total_users = User.objects.filter(is_active=True).count()

        # --- Recent reports ---
        recent = Result.objects.select_related("file").order_by("-created_at")[:5]
        recent_reports = [
            {
                "id": str(r.id),
                "filename": r.file.original_name,
                "banner": r.banner,
                "score": r.ml_score,
                "created_at": r.created_at.isoformat(),
            }
            for r in recent
        ]

        return Response({
            "today_scans": today_scans,
            "total_scans": total_scans,
            "total_users": total_users,
            "status_breakdown": status_breakdown,
            "errors_today": errors_today,
            "ml_success_rate": ml_success_rate,
            "ml_fallback_rate": ml_fallback_rate,
            "vt_success_rate": vt_success_rate,
            "recent_reports": recent_reports,
        })


# ---------------------------------------------------------------------------
# GET /api/v1/admin-panel/audit-logs/
# ---------------------------------------------------------------------------
class AuditLogListView(ListAPIView):
    """
    Searchable audit log for admin review.

    Supports filtering by: category, user email, date range, action text.
    Matches report Table 3.10 "Logs" and Figure 3.15.
    """

    permission_classes = [IsAuthenticated, IsAdmin]
    serializer_class = AuditLogSerializer

    def get_queryset(self):
        queryset = AuditLog.objects.select_related("user").all()
        params = self.request.query_params

        # Filter by category
        category = params.get("category")
        if category:
            queryset = queryset.filter(category=category)

        # Filter by user email
        user_email = params.get("user")
        if user_email:
            queryset = queryset.filter(user__email__icontains=user_email)

        # Filter by action text
        action = params.get("action")
        if action:
            queryset = queryset.filter(action__icontains=action)

        # Date range
        date_from = params.get("date_from")
        if date_from:
            queryset = queryset.filter(occurred_at__date__gte=date_from)

        date_to = params.get("date_to")
        if date_to:
            queryset = queryset.filter(occurred_at__date__lte=date_to)

        return queryset.order_by("-occurred_at")


# ---------------------------------------------------------------------------
# GET/POST /api/v1/admin-panel/yara-rules/
# ---------------------------------------------------------------------------
class YaraRuleListCreateView(APIView):
    """
    List and upload YARA rule sets.

    GET  → list all rule sets
    POST → upload a new .yar file

    Matches report Table 3.12 "YARA rules".
    """

    permission_classes = [IsAuthenticated, IsAdmin]
    parser_classes = [MultiPartParser]

    def get(self, request):
        rules = YaraRuleSet.objects.all().order_by("-updated_at")
        serializer = YaraRuleSetSerializer(rules, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = YaraRuleSetCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        rule = serializer.save(uploaded_by=request.user)

        log_audit(
            request=request,
            category="config",
            action=f"YARA rule uploaded: {rule.name} v{rule.version}",
            details={"rule_id": str(rule.id), "name": rule.name},
        )

        return Response(
            YaraRuleSetSerializer(rule).data,
            status=status.HTTP_201_CREATED,
        )


# ---------------------------------------------------------------------------
# PATCH/DELETE /api/v1/admin-panel/yara-rules/<id>/
# ---------------------------------------------------------------------------
class YaraRuleDetailView(APIView):
    """
    Update or delete a YARA rule set.

    PATCH  → enable/disable (change status)
    DELETE → remove rule set

    Matches report Table 3.12.
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def patch(self, request, id):
        try:
            rule = YaraRuleSet.objects.get(id=id)
        except YaraRuleSet.DoesNotExist:
            return Response(
                {"error": "YARA rule not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        new_status = request.data.get("status")
        if new_status and new_status in ("active", "inactive"):
            old_status = rule.status
            rule.status = new_status
            rule.save(update_fields=["status"])

            log_audit(
                request=request,
                category="config",
                action=f"YARA rule status changed: {rule.name} ({old_status} → {new_status})",
                details={"rule_id": str(rule.id)},
            )

        return Response(YaraRuleSetSerializer(rule).data)

    def delete(self, request, id):
        try:
            rule = YaraRuleSet.objects.get(id=id)
        except YaraRuleSet.DoesNotExist:
            return Response(
                {"error": "YARA rule not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        name = rule.name
        rule.delete()

        log_audit(
            request=request,
            category="config",
            action=f"YARA rule deleted: {name}",
            details={"name": name},
        )

        return Response(
            {"message": f"YARA rule '{name}' deleted."},
            status=status.HTTP_200_OK,
        )


# ---------------------------------------------------------------------------
# GET/POST /api/v1/admin-panel/ml-models/
# ---------------------------------------------------------------------------
class MLModelListCreateView(APIView):
    """
    List and upload ML model versions.

    GET  → list all model versions
    POST → upload a new model (.pkl/.joblib)

    Matches report Table 3.14 "Model".
    """

    permission_classes = [IsAuthenticated, IsAdmin]
    parser_classes = [MultiPartParser]

    def get(self, request):
        models = MLModelVersion.objects.all().order_by("-created_at")
        serializer = MLModelVersionSerializer(models, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = MLModelVersionCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        model = serializer.save(uploaded_by=request.user)

        log_audit(
            request=request,
            category="config",
            action=f"ML model uploaded: v{model.version}",
            details={"model_id": str(model.id), "version": model.version},
        )

        return Response(
            MLModelVersionSerializer(model).data,
            status=status.HTTP_201_CREATED,
        )


# ---------------------------------------------------------------------------
# POST /api/v1/admin-panel/ml-models/<id>/promote/
# ---------------------------------------------------------------------------
class MLModelPromoteView(APIView):
    """
    Promote a model version to active.

    Deactivates all other versions and sets the selected one as active.
    Matches report Table 3.14 scenario: "Upload model → Promote".
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, id):
        try:
            model = MLModelVersion.objects.get(id=id)
        except MLModelVersion.DoesNotExist:
            return Response(
                {"error": "Model version not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Deactivate all others
        MLModelVersion.objects.exclude(id=id).update(is_active=False)

        # Activate this one
        model.is_active = True
        model.save(update_fields=["is_active"])

        log_audit(
            request=request,
            category="config",
            action=f"ML model promoted: v{model.version}",
            details={"model_id": str(model.id), "version": model.version},
        )

        return Response({
            "message": f"Model v{model.version} is now active.",
            "model": MLModelVersionSerializer(model).data,
        })


# ---------------------------------------------------------------------------
# GET/POST /api/v1/admin-panel/api-keys/
# ---------------------------------------------------------------------------
class APIKeyListCreateView(APIView):
    """
    List and configure API keys.

    GET  → list all configured keys (masked)
    POST → add or rotate a key

    Matches report Table 3.13 "API keys".
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        keys = APIKeyConfig.objects.all()
        serializer = APIKeyConfigSerializer(keys, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = APIKeyConfigCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        service = serializer.validated_data["service"]
        api_key = serializer.validated_data["api_key"]

        # Update or create
        config, created = APIKeyConfig.objects.update_or_create(
            service=service,
            defaults={
                "key_hash": api_key,  # In production: encrypt this
                "status": "active",
                "configured_by": request.user,
            },
        )

        action = "added" if created else "rotated"
        log_audit(
            request=request,
            category="config",
            action=f"API key {action}: {service}",
            details={"service": service},
        )

        return Response({
            "message": f"API key for '{service}' {action} successfully.",
            "config": APIKeyConfigSerializer(config).data,
        }, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)
