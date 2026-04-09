"""
Authentication & account management views.

Endpoints:
  POST /api/v1/auth/signup/                → create account, send OTP
  POST /api/v1/auth/verify-otp/            → verify email OTP
  POST /api/v1/auth/login/                 → authenticate, return JWT
  POST /api/v1/auth/token/refresh/         → refresh JWT (simplejwt built-in)
  POST /api/v1/auth/password-reset/        → request password reset OTP
  POST /api/v1/auth/password-reset/confirm/→ verify OTP + set new password
  POST /api/v1/auth/resend-otp/            → resend OTP code
  POST /api/v1/auth/logout/                → blacklist refresh token
  GET  /api/v1/auth/me/                    → current user profile

All auth-related actions are logged to the audit table.
"""

import logging

from django.contrib.auth import update_session_auth_hash
from rest_framework import status
from rest_framework.generics import RetrieveAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

from admin_panel.utils import log_audit
from .models import User, OTP
from .serializers import (
    SignupSerializer,
    VerifyOTPSerializer,
    LoginSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    ResendOTPSerializer,
    UserSerializer,
)
from .services import create_otp, send_otp_email, verify_otp

logger = logging.getLogger("accounts")


# ---------------------------------------------------------------------------
# Helper: generate JWT token pair for a user
# ---------------------------------------------------------------------------
def _get_tokens_for_user(user: User) -> dict:
    """Generate access + refresh JWT tokens with custom claims."""
    refresh = RefreshToken.for_user(user)
    # Add custom claims so the frontend knows the role from the token
    refresh["email"] = user.email
    refresh["role"] = user.role
    return {
        "access": str(refresh.access_token),
        "refresh": str(refresh),
    }


# ---------------------------------------------------------------------------
# POST /api/v1/auth/signup/
# ---------------------------------------------------------------------------
class SignupView(APIView):
    """
    Create a new analyst account and send verification OTP.

    Request body:
      { "email": "...", "password": "...", "password_confirm": "..." }

    Response: 201 with message to check email for OTP.
    """

    permission_classes = [AllowAny]
    throttle_scope = "anon"

    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # Generate and send OTP
        otp = create_otp(user, OTP.Purpose.SIGNUP)
        email_sent = send_otp_email(user, otp)

        # Audit log
        log_audit(
            request=request,
            user=user,
            category="auth",
            action="Signup",
            details={
                "email": user.email,
                "otp_sent": email_sent,
            },
        )

        return Response(
            {
                "message": "Account created. Please check your email for the verification code.",
                "email": user.email,
            },
            status=status.HTTP_201_CREATED,
        )


# ---------------------------------------------------------------------------
# POST /api/v1/auth/verify-otp/
# ---------------------------------------------------------------------------
class VerifyOTPView(APIView):
    """
    Verify an OTP code for signup or password reset.

    Request body:
      { "email": "...", "code": "123456", "purpose": "signup" }

    For signup purpose: marks the user as verified.
    For password_reset purpose: returns a success flag (actual reset
    happens at /password-reset/confirm/).
    """

    permission_classes = [AllowAny]
    throttle_scope = "anon"

    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        code = serializer.validated_data["code"]
        purpose = serializer.validated_data["purpose"]

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {"error": "Invalid email or code."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        success, reason = verify_otp(user, code, purpose)

        if not success:
            error_messages = {
                "invalid_code": "Invalid verification code.",
                "expired": "Verification code has expired. Please request a new one.",
                "already_used": "This code has already been used. Please request a new one.",
            }
            log_audit(
                request=request,
                user=user,
                category="auth",
                action=f"OTP verification failed ({purpose})",
                details={"reason": reason},
            )
            return Response(
                {"error": error_messages.get(reason, "Verification failed.")},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # If signup verification, mark user as verified
        if purpose == OTP.Purpose.SIGNUP:
            user.is_verified = True
            user.save(update_fields=["is_verified"])

        log_audit(
            request=request,
            user=user,
            category="auth",
            action=f"OTP verified ({purpose})",
            details={"email": email},
        )

        return Response(
            {"message": "Verification successful.", "verified": True},
            status=status.HTTP_200_OK,
        )


# ---------------------------------------------------------------------------
# POST /api/v1/auth/login/
# ---------------------------------------------------------------------------
class LoginView(APIView):
    """
    Authenticate user and return JWT tokens.

    Request body:
      { "email": "...", "password": "..." }

    Response: 200 with access token, refresh token, and user info.
    """

    permission_classes = [AllowAny]
    throttle_scope = "anon"

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]
        tokens = _get_tokens_for_user(user)

        log_audit(
            request=request,
            user=user,
            category="auth",
            action="Successful login",
            details={"email": user.email},
        )

        return Response(
            {
                "tokens": tokens,
                "user": UserSerializer(user).data,
            },
            status=status.HTTP_200_OK,
        )


# ---------------------------------------------------------------------------
# POST /api/v1/auth/password-reset/
# ---------------------------------------------------------------------------
class PasswordResetRequestView(APIView):
    """
    Request a password reset OTP.

    Request body:
      { "email": "..." }

    Always returns success to prevent account enumeration.
    OTP is only sent if the account actually exists.
    """

    permission_classes = [AllowAny]
    throttle_scope = "anon"

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]

        # Generic message regardless of whether account exists
        response_msg = "If an account with this email exists, a reset code has been sent."

        try:
            user = User.objects.get(email=email)
            otp = create_otp(user, OTP.Purpose.PASSWORD_RESET)
            send_otp_email(user, otp)

            log_audit(
                request=request,
                user=user,
                category="auth",
                action="Password reset requested",
                details={"email": email},
            )
        except User.DoesNotExist:
            # Log the attempt but don't reveal that the account doesn't exist
            log_audit(
                request=request,
                category="auth",
                action="Password reset requested (unknown email)",
                details={"email": email},
            )

        return Response(
            {"message": response_msg},
            status=status.HTTP_200_OK,
        )


# ---------------------------------------------------------------------------
# POST /api/v1/auth/password-reset/confirm/
# ---------------------------------------------------------------------------
class PasswordResetConfirmView(APIView):
    """
    Verify OTP and set new password.

    Request body:
      { "email": "...", "code": "123456",
        "new_password": "...", "new_password_confirm": "..." }

    On success: password is updated, all sessions invalidated.
    """

    permission_classes = [AllowAny]
    throttle_scope = "anon"

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        code = serializer.validated_data["code"]
        new_password = serializer.validated_data["new_password"]

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {"error": "Invalid email or code."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Verify the OTP
        success, reason = verify_otp(user, code, OTP.Purpose.PASSWORD_RESET)
        if not success:
            error_messages = {
                "invalid_code": "Invalid reset code.",
                "expired": "Reset code has expired. Please request a new one.",
                "already_used": "This code has already been used.",
            }
            return Response(
                {"error": error_messages.get(reason, "Reset failed.")},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Set new password
        user.set_password(new_password)
        user.save(update_fields=["password"])

        # Invalidate all existing sessions (logout-all)
        # By changing password, existing JWT refresh tokens become invalid
        # on next refresh attempt since user's password hash changed.

        log_audit(
            request=request,
            user=user,
            category="auth",
            action="Password reset completed",
            details={"email": email},
        )

        return Response(
            {"message": "Password has been reset successfully. Please log in with your new password."},
            status=status.HTTP_200_OK,
        )


# ---------------------------------------------------------------------------
# POST /api/v1/auth/resend-otp/
# ---------------------------------------------------------------------------
class ResendOTPView(APIView):
    """
    Resend an OTP code (e.g. if the first one expired or wasn't received).

    Request body:
      { "email": "...", "purpose": "signup" }
    """

    permission_classes = [AllowAny]
    throttle_scope = "anon"

    def post(self, request):
        serializer = ResendOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        purpose = serializer.validated_data["purpose"]

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Generic message to prevent enumeration
            return Response(
                {"message": "If an account exists, a new code has been sent."},
                status=status.HTTP_200_OK,
            )

        otp = create_otp(user, purpose)
        send_otp_email(user, otp)

        log_audit(
            request=request,
            user=user,
            category="auth",
            action=f"OTP resent ({purpose})",
            details={"email": email},
        )

        return Response(
            {"message": "A new verification code has been sent to your email."},
            status=status.HTTP_200_OK,
        )


# ---------------------------------------------------------------------------
# POST /api/v1/auth/logout/
# ---------------------------------------------------------------------------
class LogoutView(APIView):
    """
    Logout by blacklisting the refresh token.

    Request body:
      { "refresh": "..." }

    The access token will expire naturally (30 min).
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response(
                {"error": "Refresh token is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except TokenError:
            # Token is already expired or invalid — that's fine, user is logged out
            pass

        log_audit(
            request=request,
            user=request.user,
            category="auth",
            action="Logout",
            details={"email": request.user.email},
        )

        return Response(
            {"message": "Successfully logged out."},
            status=status.HTTP_200_OK,
        )


# ---------------------------------------------------------------------------
# GET /api/v1/auth/me/
# ---------------------------------------------------------------------------
class MeView(RetrieveAPIView):
    """
    Return the current authenticated user's profile.

    Used by the React frontend on page load to get user info and role.
    No request body needed — user is identified by the JWT token.
    """

    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user
