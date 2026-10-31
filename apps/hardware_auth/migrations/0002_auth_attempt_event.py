import uuid

import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("hardware_auth", "0001_initial")]

    operations = [
        migrations.CreateModel(
            name="AuthAttemptEvent",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("event_id", models.UUIDField()),
                ("factor", models.CharField(choices=[("PIN", "PIN"), ("FACE", "Face"), ("FINGERPRINT", "Fingerprint")], max_length=16)),
                ("protocol_version", models.PositiveSmallIntegerField(default=1)),
                ("evidence_class", models.CharField(default="CLIENT_ASSERTION", max_length=32)),
                ("verified", models.BooleanField(default=False, editable=False)),
                ("occurred_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("attempt", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="events", to="hardware_auth.authattempt")),
            ],
            options={"db_table": "auth_attempt_event", "ordering": ["occurred_at"]},
        ),
        migrations.AddConstraint(
            model_name="authattemptevent",
            constraint=models.UniqueConstraint(fields=("attempt", "event_id"), name="uniq_attempt_event_id"),
        ),
        migrations.AddConstraint(
            model_name="authattemptevent",
            constraint=models.CheckConstraint(condition=models.Q(verified=False), name="attempt_event_never_verified"),
        ),
        migrations.AddConstraint(
            model_name="authattemptevent",
            constraint=models.UniqueConstraint(fields=("attempt", "factor"), name="uniq_attempt_factor_report"),
        ),
    ]
