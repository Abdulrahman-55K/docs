"""
Custom User model for the Malicious Document Detector.

Maps to the USERS table in the ER diagram:
  id | email | password_hash | role

Uses Django's AbstractUser but swaps username for email-based login
and adds the role field (analyst/admin) for RBAC.
"""

import uuid
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models


class UserManager(BaseUserManager):
    """Manager that uses email instead of username."""

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email is required")
        email = self.normalize_email(email)
        extra_fields.setdefault("role", "analyst")  # least privilege
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("role", "admin")
        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    """Custom user: email-based auth with analyst/admin roles."""

    class Role(models.TextChoices):
        ANALYST = "analyst", "Analyst"
        ADMIN = "admin", "Admin"

    # Remove username, use email as the unique identifier
    username = None
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=10, choices=Role.choices, default=Role.ANALYST)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []  # email & password handled by createsuperuser prompt

    objects = UserManager()

    class Meta:
        db_table = "users"
        verbose_name = "user"
        verbose_name_plural = "users"

    def __str__(self):
        return f"{self.email} ({self.role})"

    @property
    def is_admin(self):
        return self.role == self.Role.ADMIN

    @property
    def is_analyst(self):
        return self.role == self.Role.ANALYST


class OTP(models.Model):
    """
    One-Time Password for email verification and password reset.

    - Single use, time-limited (5 min default)
    - Linked to a purpose so signup OTPs can't be reused for password reset
    """

    class Purpose(models.TextChoices):
        SIGNUP = "signup", "Account Verification"
        PASSWORD_RESET = "password_reset", "Password Reset"
        LOGIN = "login", "Login Verification"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="otps")
    code = models.CharField(max_length=6)
    purpose = models.CharField(max_length=20, choices=Purpose.choices)
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    class Meta:
        db_table = "otps"
        ordering = ["-created_at"]

    def __str__(self):
        return f"OTP for {self.user.email} ({self.purpose})"
