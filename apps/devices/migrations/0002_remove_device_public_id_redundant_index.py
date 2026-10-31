from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("devices", "0001_initial")]

    operations = [
        migrations.AlterField(
            model_name="device",
            name="device_public_id",
            field=models.CharField(max_length=128, unique=True),
        ),
    ]
