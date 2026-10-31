"""
Management command to bootstrap the single designated administrator account.

Security controls:
- Enforces single-admin policy with database locking (select_for_update inside an atomic transaction).
- Rejects execution if an administrator account already exists.
- Validates password against Django password validators (minimum length, complexity, common patterns).
- Passwords are never echoed or written to audit logs.
- Records an append-only audit event for accountability.
"""

import getpass
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.accounts.models import AdminBootstrapLock, UserRole
from apps.audit.services import record_audit_event

User = get_user_model()


class Command(BaseCommand):
    help = "Bootstrap the initial designated administrator account (single-admin policy)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--username",
            type=str,
            required=False,
            help="Username for the administrator account.",
        )
        parser.add_argument(
            "--password",
            type=str,
            required=False,
            help="Password for the administrator account (prompted interactively if omitted).",
        )
        parser.add_argument(
            "--no-input",
            action="store_true",
            help="Do not prompt for input if arguments are missing.",
        )

    def handle(self, *args, **options):
        username = options.get("username")
        password = options.get("password")
        no_input = options.get("no_input", False)

        if not username:
            if no_input:
                raise CommandError("--username is required when running with --no-input.")
            username = input("Enter admin username: ").strip()

        username = username.strip()
        if not username:
            raise CommandError("Username cannot be blank.")

        if not password:
            if no_input:
                raise CommandError("--password is required when running with --no-input.")
            password = getpass.getpass("Enter admin password: ")
            password_confirm = getpass.getpass("Confirm admin password: ")
            if password != password_confirm:
                raise CommandError("Passwords do not match.")

        # Validate password strength according to configured validators
        try:
            validate_password(password, User(username=username))
        except ValidationError as e:
            raise CommandError(f"Password does not meet security requirements: {'; '.join(e.messages)}")

        with transaction.atomic():
            # Lock a persistent singleton row; locking an empty admin query
            # does not serialize concurrent bootstrap attempts on PostgreSQL.
            AdminBootstrapLock.objects.get_or_create(key="singleton")
            AdminBootstrapLock.objects.select_for_update().get(key="singleton")
            existing_admin = User.objects.filter(role=UserRole.ADMIN).first()
            if existing_admin:
                raise CommandError(
                    f"Bootstrap rejected: An administrator account ({existing_admin.username}) already exists. "
                    "Only one designated administrator is permitted."
                )

            # Check if username already taken by another account
            if User.objects.filter(username=username).exists():
                raise CommandError(f"Username '{username}' is already in use.")

            admin_user = User.objects.create_superuser(
                username=username,
                password=password,
            )

            record_audit_event(
                event_type="ADMIN_BOOTSTRAP",
                result="SUCCESS",
                actor_user=admin_user,
                safe_metadata={"username": username},
                strict=True,
            )

        self.stdout.write(
            self.style.SUCCESS(
                f"Successfully bootstrapped designated administrator account '{username}' (ID: {admin_user.id})."
            )
        )
