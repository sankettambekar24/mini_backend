from django.db import migrations, models


def create_singleton_lock(apps, schema_editor):
    Lock = apps.get_model("accounts", "AdminBootstrapLock")
    Lock.objects.get_or_create(key="singleton")


class Migration(migrations.Migration):
    dependencies = [("accounts", "0002_user_token_version")]

    operations = [
        migrations.CreateModel(
            name="AdminBootstrapLock",
            fields=[
                (
                    "key",
                    models.CharField(
                        default="singleton", editable=False, max_length=32, primary_key=True, serialize=False
                    ),
                ),
            ],
            options={"db_table": "admin_bootstrap_lock"},
        ),
        migrations.RunPython(create_singleton_lock, migrations.RunPython.noop),
    ]
