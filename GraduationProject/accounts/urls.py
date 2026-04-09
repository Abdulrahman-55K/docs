"""
Authentication & account management endpoints.

All routes are prefixed with /api/v1/auth/ (see core/urls.py).

Endpoint map:
  POST  signup/                → create account, send verification OTP
  POST  verify-otp/            → verify OTP (signup or password reset)
  POST  resend-otp/            → resend OTP code
  POST  login/                 → authenticate, get JWT tokens
  POST  token/refresh/         → refresh expired access token
  POST  password-reset/        → request password reset OTP
  POST  password-reset/confirm/→ verify OTP + set new password
  POST  logout/                → blacklist refresh token
  GET   me/                    → current user profile + role
"""

from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    SignupView,
    VerifyOTPView,
    LoginView,
    PasswordResetRequestView,
    PasswordResetConfirmView,
    ResendOTPView,
    LogoutView,
    MeView,
)

urlpatterns = [
    # Registration
    path("signup/", SignupView.as_view(), name="signup"),
    path("verify-otp/", VerifyOTPView.as_view(), name="verify-otp"),
    path("resend-otp/", ResendOTPView.as_view(), name="resend-otp"),

    # Authentication
    path("login/", LoginView.as_view(), name="login"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("logout/", LogoutView.as_view(), name="logout"),

    # Password reset
    path("password-reset/", PasswordResetRequestView.as_view(), name="password-reset"),
    path("password-reset/confirm/", PasswordResetConfirmView.as_view(), name="password-reset-confirm"),

    # User profile
    path("me/", MeView.as_view(), name="me"),
]
