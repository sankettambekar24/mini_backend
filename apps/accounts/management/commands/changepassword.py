"""Change a password and revoke prior credentials in one audited transaction."""

import getpass

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import CommandError
from django.db import DEFAULT_DB_ALIAS, transaction
from django.contrib.auth.management.commands.changepassword import Command as DjangoChangePasswordCommand

from apps.audit.services import record_audit_event

User = get_user_model()


class Command(DjangoChangePasswordCommand):
    def handle(self, *args, **options):
        username = options["username"] or getpass.getuser()
        database = options.get("database", DEFAULT_DB_ALIAS)
        manager = User._default_manager.using(database)
        try:
            user = manager.get(**{User.USERNAME_FIELD: username})
        except User.DoesNotExist as exc:
            raise CommandError(f"user '{username}' does not exist") from exc

        self.stdout.write(f"Changing password for user '{user}'")
        count = 0
        validated = False
        password = ""
        while count < 3 and not validated:
            password = self._get_pass()
            confirmation = self._get_pass("Password (again): ")
            if password != confirmation:
                self.stdout.write("Passwords do not match. Please try again.")
                count += 1
                continue
            try:
                validate_password(confirmation, user)
            except ValidationError as err:
                self.stderr.write("\n".join(err.messages))
                count += 1
            else:
                validated = True
        if not validated:
            raise CommandError(f"Aborting password change for user '{user}' after {count} attempts")

        with transaction.atomic(using=database):
            user = manager.select_for_update().get(pk=user.pk)
            user.set_password(password)
            user.token_version += 1
            user.save(using=database, update_fields=["password", "token_version", "updated_at"])
            record_audit_event(
                "PASSWORD_CHANGED", "SUCCESS", actor_user=user,
                safe_metadata={"source": "management_command"}, strict=True,
                using=database,
            )
        return f"Password changed successfully for user '{user}'"
