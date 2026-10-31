from rest_framework import serializers
from apps.audit.models import AuditEvent


class AuditEventSerializer(serializers.ModelSerializer):
    actor_username = serializers.SerializerMethodField()

    class Meta:
        model = AuditEvent
        fields = [
            "id", "occurred_at", "actor_username", "event_type",
            "result", "correlation_id", "safe_metadata",
        ]
        read_only_fields = fields

    def get_actor_username(self, obj):
        if obj.actor_user:
            return obj.actor_user.username
        return None
