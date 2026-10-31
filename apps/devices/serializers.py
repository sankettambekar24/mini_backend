from django.contrib.auth import get_user_model
from rest_framework import serializers

from apps.devices.models import Device, DeviceStatus

User = get_user_model()


class DeviceSerializer(serializers.ModelSerializer):
    owner_user_id = serializers.UUIDField(source="owner_user.id", read_only=True, allow_null=True)

    class Meta:
        model = Device
        fields = ["id", "device_label", "device_public_id", "owner_user_id", "status",
                  "protocol_version", "last_seen_at", "created_at", "updated_at", "revoked_at"]
        read_only_fields = fields


class DeviceEnrollmentSerializer(serializers.ModelSerializer):
    owner_user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), required=False, allow_null=True)

    class Meta:
        model = Device
        fields = ["id", "device_label", "device_public_id", "protocol_version", "owner_user", "status"]
        read_only_fields = ["id", "status"]

    def create(self, validated_data):
        return Device.objects.create(status=DeviceStatus.PENDING, **validated_data)


class DeviceStatusSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=DeviceStatus.choices)


class DeviceAssignmentSerializer(serializers.Serializer):
    owner_user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), allow_null=True, required=True)
