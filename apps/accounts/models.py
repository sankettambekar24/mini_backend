"""
Custom user model for the Hybrid Secure Storage System.

This model is configured as AUTH_USER_MODEL and must never be changed
after the first migration without a carefully planned migration strategy.
"""

import uuid

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.contrib.auth.password_validation import validate_password
from django.db import models, transaction
from django.utils import timezone


class UserRole(models.TextChoices):
    ADMIN = "ADMIN", "Admin"
    USER = "USER", "User"


class AdminBootstrapLock(models.Model):
    """Persistent row used to serialize initial administrator creation."""

    key = models.CharField(max_length=32, primary_key=True, default="singleton", editable=False)

    class Meta:
        db_table = "admin_bootstrap_lock"


class UserManager(BaseUserManager):
    def _create_user(self, username, password, role, **extra_fields):
        if not username:
            raise ValueError("Username is required")
        username = self.model.normalize_username(username)
        user = self.model(username=username, role=role, **extra_fields)
        if password is not None:
            # Enforce policy for every manager-based creation path, including
            # management commands and internal callers outside the API.
            validate_password(password, user)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, username, password=None, **extra_fields):
        """Create a standard USER. Admin role cannot be set via this method."""
        extra_fields.setdefault("role", UserRole.USER)
        if extra_fields.get("role") == UserRole.ADMIN:
            raise ValueError(
                "Regular users cannot be created with the ADMIN role. "
                "Use create_superuser or the admin bootstrap process."
            )
        return self._create_user(username, password, extra_fields.pop("role"), **extra_fields)

    def create_superuser(self, username, password=None, **extra_fields):
        """Create the single designated administrator under the shared lock."""
        extra_fields["is_staff"] = True
        extra_fields["is_superuser"] = True
        # Remove 'role' from extra_fields before passing to _create_user
        # since role is passed as a positional argument.
        extra_fields.pop("role", None)
        with transaction.atomic(using=self._db):
            AdminBootstrapLock.objects.using(self._db).get_or_create(key="singleton")
            AdminBootstrapLock.objects.using(self._db).select_for_update().get(key="singleton")
            if self.model.objects.using(self._db).filter(role=UserRole.ADMIN).exists():
                raise ValueError("The designated administrator already exists.")
            return self._create_user(username, password, UserRole.ADMIN, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom user model for the Hybrid Secure Storage System.

    Security notes:
    - Passwords are stored using Django's password hashers (never plaintext).
    - PINs are NOT stored here; they are a separate hardware factor.
    - UUID primary key prevents sequential ID enumeration.
    - Role assignment requires an authorized admin action (enforced in views).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=64, unique=True, db_index=True)
    email = models.EmailField(blank=True, default="")

    role = models.CharField(
        max_length=10,
        choices=UserRole.choices,
        default=UserRole.USER,
    )

    # Django admin compatibility
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    # Active flag: inactive users cannot log in
    is_active = models.BooleanField(default=True)

    # Token version: incrementing this invalidates all previously issued access tokens
    token_version = models.PositiveIntegerField(default=1)

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    last_login_at = models.DateTimeField(null=True, blank=True)

    objects = UserManager()

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = []

    class Meta:
        db_table = "accounts_user"
        ordering = ["created_at"]

    def __str__(self):
        return f"{self.username} ({self.role})"

    @property
    def is_admin(self):
        return self.role == UserRole.ADMIN

    def revoke_tokens(self):
        """Invalidate all previously issued JWT access tokens for this user."""
        self.token_version += 1
        self.save(update_fields=["token_version", "updated_at"])

    def safe_profile(self):
        """Return a safe subset of fields for API responses. Never include password hashes."""
        return {
            "id": str(self.id),
            "username": self.username,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
        }
