import django.db.models.deletion
import django.utils.timezone
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("hardware_auth", "0003_alter_authattempt_status")]

    operations = [
        migrations.CreateModel(
            name="AuthAttemptCapability",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("token_digest", models.CharField(max_length=64, unique=True)),
                ("expires_at", models.DateTimeField(db_index=True)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ("attempt", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="preauth_capability", to="hardware_auth.authattempt")),
            ],
            options={"db_table": "auth_attempt_capability"},
        ),
    ]
