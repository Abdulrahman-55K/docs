"""
Custom permission classes for Role-Based Access Control.

Two roles from the report:
  - Analyst: upload, view own reports, search, export
  - Admin:   everything Analyst can do + rule/model/key management,
             view all reports, audit logs, dashboard
"""

from rest_framework.permissions import BasePermission


class IsAdmin(BasePermission):
    """Allow access only to users with admin role."""

    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and request.user.role == "admin"
        )


class IsAnalyst(BasePermission):
    """Allow access only to users with analyst role."""

    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and request.user.role == "analyst"
        )


class IsAnalystOrAdmin(BasePermission):
    """Allow access to both analyst and admin roles."""

    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and request.user.role in ("analyst", "admin")
        )
