"""
Centralized audit logging utility.

Usage from any view or service:
    from admin_panel.utils import log_audit

    log_audit(
        request=request,
        category="auth",
        action="Successful login",
        details={"method": "jwt"},
    )

Guest users are identified as "Guest [token[:8]] (IP: x.x.x.x)"
in the action log so every upload is traceable even without an account.
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


def get_actor_label(request) -> str:
    """
    Build a human-readable actor label for the audit log.

    Authenticated user  → their email address
    Guest               → "Guest [token[:8]] (IP: x.x.x.x)"
    No request          → "system"
    """
    if request is None:
        return "system"

    if request.user and request.user.is_authenticated:
        return request.user.email

    # Guest: identify by token + IP so every action is traceable
    guest_token = request.headers.get("X-Guest-Token", "").strip()[:64]
    ip = get_client_ip(request) or "unknown"

    if guest_token:
        return f"Guest [{guest_token[:8]}] (IP: {ip})"
    return f"Guest (IP: {ip})"


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
        user = request.user if (request.user and request.user.is_authenticated) else None

    actor = get_actor_label(request)

    # Store actor label in details so it's visible even when user FK is null
    log_details = details or {}
    if user is None and request is not None:
        log_details = {"actor": actor, **log_details}

    entry = AuditLog.objects.create(
        user=user,
        category=category,
        action=action,
        ip_address=get_client_ip(request),
        details_json=log_details,
    )
    logger.info("AUDIT | %s | %s | %s", actor, action, log_details)
    return entry
    