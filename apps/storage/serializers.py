"""Serializers for metadata-only file authorization APIs."""

from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework import serializers

from apps.permissions.models import PermissionType
from apps.storage.models import StoredFileMetadata

User = get_user_model()


class StrictInputSerializer(serializers.Serializer):
    """Reject undeclared fields instead of silently accepting client claims."""

    def to_internal_value(self, data):
        if hasattr(data, "keys"):
            unknown = set(data.keys()) - set(self.fields.keys())
            if unknown:
                raise serializers.ValidationError(
                    {"non_field_errors": ["Unknown fields are not accepted."]}
                )
        return super().to_internal_value(data)


class FileMetadataSerializer(serializers.ModelSerializer):
    owner_user_id = serializers.UUIDField(read_only=True)
    content_available = serializers.SerializerMethodField()

    class Meta:
        model = StoredFileMetadata
        fields = [
            "id", "owner_user_id", "display_name", "size_bytes",
            "encryption_format_version", "created_at", "updated_at",
            "content_available",
        ]
        read_only_fields = fields

    def get_content_available(self, obj):
        # This phase registers metadata only; no object storage is connected.
        return False


class FileMetadataCreateSerializer(StrictInputSerializer):
    owner_user_id = serializers.PrimaryKeyRelatedField(
        source="owner_user", queryset=User.objects.filter(is_active=True)
    )
    display_name = serializers.CharField(max_length=255, trim_whitespace=True)

    def validate_display_name(self, value):
        if value in {".", ".."} or "/" in value or "\\" in value:
            raise serializers.ValidationError("Use a display name, not a path.")
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise serializers.ValidationError("Control characters are not allowed.")
        return value


class FileGrantCreateSerializer(StrictInputSerializer):
    subject_user_id = serializers.PrimaryKeyRelatedField(
        source="subject_user", queryset=User.objects.filter(is_active=True)
    )
    permission = serializers.ChoiceField(
        choices=[PermissionType.LIST.value, PermissionType.READ.value]
    )
    expires_at = serializers.DateTimeField(required=False, allow_null=True)

    def validate_expires_at(self, value):
        if value is not None and value <= timezone.now():
            raise serializers.ValidationError("Grant expiry must be in the future.")
        return value


class FileGrantSerializer(serializers.Serializer):
    id = serializers.UUIDField(read_only=True)
    subject_user_id = serializers.UUIDField(read_only=True)
    granted_by_user_id = serializers.UUIDField(source="granted_by_id", read_only=True, allow_null=True)
    permission = serializers.CharField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)
    expires_at = serializers.DateTimeField(read_only=True, allow_null=True)
    revoked_at = serializers.DateTimeField(read_only=True, allow_null=True)
    active = serializers.SerializerMethodField()

    def get_active(self, obj):
        return obj.is_active()
