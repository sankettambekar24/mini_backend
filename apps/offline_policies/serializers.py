from rest_framework import serializers

from apps.offline_policies.models import OfflinePolicy


class OfflinePolicySerializer(serializers.ModelSerializer):
    user_id = serializers.UUIDField(read_only=True)
    device_id = serializers.UUIDField(read_only=True)
    file_scopes = serializers.SerializerMethodField()

    class Meta:
        model = OfflinePolicy
        fields = [
            "id", "policy_id", "policy_version", "schema_version", "user_id", "device_id",
            "device_key_id", "status", "max_offline_seconds", "issued_at", "expires_at",
            "signing_key_id", "revoked_at", "revocation_reason", "superseded_by", "file_scopes",
            "created_at", "updated_at",
        ]
        read_only_fields = fields

    def get_file_scopes(self, obj):
        return [
            {"file_id": str(row.file_id), "scope": row.scope}
            for row in obj.file_scopes.select_related("file").order_by("file_id", "scope")
        ]
