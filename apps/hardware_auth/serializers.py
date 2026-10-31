from rest_framework import serializers

from apps.hardware_auth.models import AuthAttempt, AuthAttemptEvent


class AuthAttemptCreateSerializer(serializers.Serializer):
    device_id = serializers.UUIDField()


class FactorReportSerializer(serializers.Serializer):
    contract_version = serializers.IntegerField(min_value=1, max_value=1)
    event_id = serializers.UUIDField()
    device_id = serializers.UUIDField()
    factor = serializers.ChoiceField(choices=AuthAttemptEvent.Factor.choices)


class AttemptBindingSerializer(serializers.Serializer):
    device_id = serializers.UUIDField()


class AuthAttemptEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuthAttemptEvent
        fields = ["id", "event_id", "factor", "protocol_version", "evidence_class", "verified", "occurred_at"]


class AuthAttemptSerializer(serializers.ModelSerializer):
    user_id = serializers.UUIDField(read_only=True)
    device_id = serializers.UUIDField(read_only=True)
    events = AuthAttemptEventSerializer(many=True, read_only=True)

    class Meta:
        model = AuthAttempt
        fields = ["id", "user_id", "device_id", "status", "required_factors",
                  "created_at", "expires_at", "completed_at", "failure_code", "events"]
        read_only_fields = fields
