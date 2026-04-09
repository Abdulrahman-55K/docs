"""
OTP generation, delivery, and verification service.

Handles all OTP flows:
  - Signup email verification
  - Password reset
  - Login 2FA (optional)

OTPs are 6-digit, single-use, and expire after 5 minutes (configurable).
"""

import random
import logging
from datetime import timedelta

from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone

from .models import OTP, User

logger = logging.getLogger("accounts")


def generate_otp_code() -> str:
    """Generate a random 6-digit OTP code."""
    length = getattr(settings, "OTP_LENGTH", 6)
    return "".join([str(random.randint(0, 9)) for _ in range(length)])


def create_otp(user: User, purpose: str) -> OTP:
    """
    Create a new OTP for the given user and purpose.

    Invalidates any previous unused OTPs for the same user+purpose
    to prevent confusion with stale codes.
    """
    # Invalidate old unused OTPs for this user+purpose
    OTP.objects.filter(
        user=user,
        purpose=purpose,
        is_used=False,
    ).update(is_used=True)

    expiry_minutes = getattr(settings, "OTP_EXPIRY_MINUTES", 5)
    otp = OTP.objects.create(
        user=user,
        code=generate_otp_code(),
        purpose=purpose,
        expires_at=timezone.now() + timedelta(minutes=expiry_minutes),
    )
    logger.info("OTP created for %s (purpose=%s)", user.email, purpose)
    return otp


def send_otp_email(user: User, otp: OTP) -> bool:
    """
    Send OTP code via email.

    Returns True if sent successfully, False otherwise.
    In development (console backend), the OTP prints to terminal.
    """
    subject_map = {
        OTP.Purpose.SIGNUP: "Verify your account — MalDoc Detector",
        OTP.Purpose.PASSWORD_RESET: "Password reset code — MalDoc Detector",
        OTP.Purpose.LOGIN: "Login verification code — MalDoc Detector",
    }
    subject = subject_map.get(otp.purpose, "Your verification code")

    message = (
        f"Hello,\n\n"
        f"Your verification code is: {otp.code}\n\n"
        f"This code expires in {getattr(settings, 'OTP_EXPIRY_MINUTES', 5)} minutes.\n"
        f"If you did not request this, please ignore this email.\n\n"
        f"— MalDoc Detector Team"
    )

    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
        logger.info("OTP email sent to %s (purpose=%s)", user.email, otp.purpose)
        return True
    except Exception as e:
        logger.error("OTP email failed for %s: %s", user.email, str(e))
        return False


def verify_otp(user: User, code: str, purpose: str) -> tuple[bool, str]:
    """
    Verify an OTP code for the given user and purpose.

    Returns:
        (True, "ok")                — success
        (False, "invalid_code")     — no matching OTP found
        (False, "expired")          — OTP found but expired
        (False, "already_used")     — OTP already consumed
    """
    try:
        otp = OTP.objects.filter(
            user=user,
            code=code,
            purpose=purpose,
        ).latest("created_at")
    except OTP.DoesNotExist:
        logger.warning("OTP verification failed: invalid code for %s", user.email)
        return False, "invalid_code"

    if otp.is_used:
        logger.warning("OTP verification failed: already used for %s", user.email)
        return False, "already_used"

    if timezone.now() > otp.expires_at:
        logger.warning("OTP verification failed: expired for %s", user.email)
        return False, "expired"

    # Mark as used (single-use)
    otp.is_used = True
    otp.save(update_fields=["is_used"])

    logger.info("OTP verified successfully for %s (purpose=%s)", user.email, purpose)
    return True, "ok"
