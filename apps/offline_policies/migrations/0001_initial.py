import django.db.models.deletion
import django.utils.timezone
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("devices", "0001_initial"),
        ("storage", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="OfflinePolicy",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("policy_id", models.UUIDField(db_index=True, default=uuid.uuid4)),
                ("policy_version", models.PositiveIntegerField(default=1)),
                ("schema_version", models.PositiveSmallIntegerField(default=1)),
                ("nonce", models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ("device_key_id", models.CharField(blank=True, default="", max_length=128)),
                ("status", models.CharField(choices=[("PREPARED", "Prepared"), ("ISSUED", "Issued"), ("REVOKED", "Revoked"), ("EXPIRED", "Expired"), ("SUPERSEDED", "Superseded")], db_index=True, default="PREPARED", max_length=16)),
                ("max_offline_seconds", models.PositiveIntegerField()),
                ("issued_at", models.DateTimeField(blank=True, null=True)),
                ("expires_at", models.DateTimeField(blank=True, db_index=True, null=True)),
                ("signing_key_id", models.CharField(blank=True, default="", max_length=128)),
                ("signed_policy", models.TextField(blank=True, default="")),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("revocation_reason", models.CharField(blank=True, default="", max_length=64)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("device", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="offline_policies", to="devices.device")),
                ("revoked_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name="revoked_offline_policies", to=settings.AUTH_USER_MODEL)),
                ("superseded_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name="supersedes", to="offline_policies.offlinepolicy")),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="offline_policies", to=settings.AUTH_USER_MODEL)),
            ],
            options={"db_table": "offline_policy", "ordering": ["-created_at"]},
        ),
        migrations.CreateModel(
            name="OfflinePolicyFileScope",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("scope", models.CharField(choices=[("LIST", "List"), ("READ", "Read")], max_length=8)),
                ("file", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="offline_policy_scopes", to="storage.storedfilemetadata")),
                ("policy", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="file_scopes", to="offline_policies.offlinepolicy")),
            ],
            options={"db_table": "offline_policy_file_scope"},
        ),
        migrations.AddField(
            model_name="offlinepolicy",
            name="scopes",
            field=models.ManyToManyField(related_name="offline_policies", through="offline_policies.OfflinePolicyFileScope", to="storage.storedfilemetadata"),
        ),
        migrations.AddConstraint(
            model_name="offlinepolicy",
            constraint=models.UniqueConstraint(fields=("policy_id", "policy_version"), name="uniq_offline_policy_version"),
        ),
        migrations.AddConstraint(
            model_name="offlinepolicyfilescope",
            constraint=models.UniqueConstraint(fields=("policy", "file", "scope"), name="uniq_offline_policy_file_scope"),
        ),
    ]
