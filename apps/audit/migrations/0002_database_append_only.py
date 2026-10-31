from django.db import migrations, models
import django.db.models.deletion


def install_append_only_triggers(apps, schema_editor):
    vendor = schema_editor.connection.vendor
    cursor = schema_editor.connection.cursor()
    if vendor == "sqlite":
        cursor.execute("""
            CREATE TRIGGER audit_event_no_update
            BEFORE UPDATE ON audit_event
            BEGIN SELECT RAISE(ABORT, 'audit_event is append-only'); END;
        """)
        cursor.execute("""
            CREATE TRIGGER audit_event_no_delete
            BEFORE DELETE ON audit_event
            BEGIN SELECT RAISE(ABORT, 'audit_event is append-only'); END;
        """)
    elif vendor == "postgresql":
        cursor.execute("""
            CREATE FUNCTION reject_audit_event_mutation() RETURNS trigger AS $$
            BEGIN RAISE EXCEPTION 'audit_event is append-only'; END;
            $$ LANGUAGE plpgsql;
        """)
        cursor.execute("""
            CREATE TRIGGER audit_event_no_mutation
            BEFORE UPDATE OR DELETE ON audit_event
            FOR EACH ROW EXECUTE FUNCTION reject_audit_event_mutation();
        """)


def remove_append_only_triggers(apps, schema_editor):
    vendor = schema_editor.connection.vendor
    cursor = schema_editor.connection.cursor()
    if vendor == "sqlite":
        cursor.execute("DROP TRIGGER IF EXISTS audit_event_no_update")
        cursor.execute("DROP TRIGGER IF EXISTS audit_event_no_delete")
    elif vendor == "postgresql":
        cursor.execute("DROP TRIGGER IF EXISTS audit_event_no_mutation ON audit_event")
        cursor.execute("DROP FUNCTION IF EXISTS reject_audit_event_mutation()")


class Migration(migrations.Migration):
    dependencies = [("audit", "0001_initial")]

    operations = [
        migrations.AlterField(
            model_name="auditevent",
            name="actor_user",
            field=models.ForeignKey(
                blank=True,
                db_index=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="audit_events",
                to="accounts.user",
            ),
        ),
        migrations.RunPython(install_append_only_triggers, remove_append_only_triggers),
    ]
