"""
Centralized audit logging utility.

Usage from any view or service:
    from admin_panel.utils import log_audit

    log_audit(
        request=request,           # or None for system events
        category="auth",
        action="Successful login",
        details={"method": "jwt"},
    )
"""

import logging
from admin_panel.models import AuditLog

logger = logging.getLogger("admin_panel")


def get_client_ip(request) -> str | None:
    """Extract the real client IP, respecting X-Forwarded-For."""
    if request is None:
        return None
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def log_audit(
    request=None,
    user=None,
    category: str = "admin",
    action: str = "",
    details: dict | None = None,
) -> AuditLog:
    """
    Create an append-only audit log entry.

    Accepts either a request (to auto-extract user + IP)
    or an explicit user for background tasks.
    """
    if user is None and request is not None:
        user = request.user if request.user.is_authenticated else None

    entry = AuditLog.objects.create(
        user=user,
        category=category,
        action=action,
        ip_address=get_client_ip(request),
        details_json=details or {},
    )
    logger.info("AUDIT | %s | %s | %s", user, action, details or "")
    return entry
