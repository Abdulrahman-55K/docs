"""
Authentication & account management endpoints.

All routes are prefixed with /api/v1/auth/ (see core/urls.py).
Endpoints will be implemented in Step 3.
"""

from django.urls import path

urlpatterns = [
    # Step 3 will add:
    # POST  signup/            → create account, send OTP
    # POST  verify-otp/        → verify email OTP
    # POST  login/             → authenticate, return JWT
    # POST  token/refresh/     → refresh JWT
    # POST  password-reset/    → request password reset OTP
    # POST  password-reset/confirm/  → verify OTP + set new password
    # POST  logout/            → blacklist refresh token
    # GET   me/                → current user profile
]
