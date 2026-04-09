"""
Serializers for authentication and account management.

Each serializer handles input validation for its endpoint:
  - SignupSerializer         → POST /api/v1/auth/signup/
  - VerifyOTPSerializer      → POST /api/v1/auth/verify-otp/
  - LoginSerializer          → POST /api/v1/auth/login/
  - PasswordResetSerializer  → POST /api/v1/auth/password-reset/
  - PasswordResetConfirmSerializer → POST /api/v1/auth/password-reset/confirm/
  - UserSerializer           → GET  /api/v1/auth/me/
"""

from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers

from .models import User


class SignupSerializer(serializers.Serializer):
    """
    Validate signup input: email + password + confirm password.

    Creates user in unverified state. OTP is sent separately in the view.
    """

    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True, min_length=8)

    def validate_email(self, value):
        email = value.lower().strip()
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError("An account with this email already exists.")
        return email

    def validate_password(self, value):
        # Run Django's built-in password validators (length, common, numeric)
        validate_password(value)
        return value

    def validate(self, data):
        if data["password"] != data["password_confirm"]:
            raise serializers.ValidationError({"password_confirm": "Passwords do not match."})
        return data

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data["email"],
            password=validated_data["password"],
        )
        # User starts as unverified — must confirm OTP
        user.is_verified = False
        user.is_active = True  # active but unverified
        user.save(update_fields=["is_verified"])
        return user


class VerifyOTPSerializer(serializers.Serializer):
    """
    Validate OTP verification input.

    Used for both signup verification and password reset verification.
    """

    email = serializers.EmailField()
    code = serializers.CharField(max_length=6, min_length=6)
    purpose = serializers.ChoiceField(choices=["signup", "password_reset", "login"])

    def validate_email(self, value):
        return value.lower().strip()


class LoginSerializer(serializers.Serializer):
    """
    Validate login credentials.

    Authenticates with email + password, checks that account
    is verified and active.
    """

    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate_email(self, value):
        return value.lower().strip()

    def validate(self, data):
        user = authenticate(
            username=data["email"],  # Django auth uses 'username' param
            password=data["password"],
        )

        if user is None:
            raise serializers.ValidationError("Invalid email or password.")

        if not user.is_active:
            raise serializers.ValidationError("This account has been deactivated.")

        if not user.is_verified:
            raise serializers.ValidationError(
                "Email not verified. Please check your email for the verification code."
            )

        data["user"] = user
        return data


class PasswordResetRequestSerializer(serializers.Serializer):
    """
    Validate password reset request — just needs the email.

    Uses a generic success message even if email doesn't exist
    to prevent account enumeration.
    """

    email = serializers.EmailField()

    def validate_email(self, value):
        return value.lower().strip()


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Validate password reset confirmation: email + OTP + new password.
    """

    email = serializers.EmailField()
    code = serializers.CharField(max_length=6, min_length=6)
    new_password = serializers.CharField(write_only=True, min_length=8)
    new_password_confirm = serializers.CharField(write_only=True, min_length=8)

    def validate_email(self, value):
        return value.lower().strip()

    def validate_new_password(self, value):
        validate_password(value)
        return value

    def validate(self, data):
        if data["new_password"] != data["new_password_confirm"]:
            raise serializers.ValidationError(
                {"new_password_confirm": "Passwords do not match."}
            )
        return data


class ResendOTPSerializer(serializers.Serializer):
    """Validate resend OTP request."""

    email = serializers.EmailField()
    purpose = serializers.ChoiceField(choices=["signup", "password_reset", "login"])

    def validate_email(self, value):
        return value.lower().strip()


class UserSerializer(serializers.ModelSerializer):
    """
    Read-only user profile for the /me/ endpoint.

    Returns user info needed by the React frontend to
    determine role and display user details.
    """

    class Meta:
        model = User
        fields = ["id", "email", "role", "is_verified", "created_at"]
        read_only_fields = fields
