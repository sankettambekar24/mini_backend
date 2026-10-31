from django.db import transaction
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.permissions import IsAdminRole
from apps.devices.models import Device
from apps.devices.serializers import (
    DeviceAssignmentSerializer,
    DeviceEnrollmentSerializer,
    DeviceSerializer,
    DeviceStatusSerializer,
)
from apps.devices.services import assign_device, change_device_status


class DeviceListCreateView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = DeviceSerializer

    def get_queryset(self):
        qs = Device.objects.select_related("owner_user").all()
        if self.request.user.is_admin:
            return qs
        return qs.filter(owner_user=self.request.user)

    def get_serializer_class(self):
        return DeviceEnrollmentSerializer if self.request.method == "POST" else DeviceSerializer

    def get_permissions(self):
        if self.request.method == "POST":
            return [IsAuthenticated(), IsAdminRole()]
        return [IsAuthenticated()]

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)

    def perform_create(self, serializer):
        device = serializer.save()
        from apps.audit.services import record_audit_event
        record_audit_event(
            "DEVICE_ENROLLED", "PENDING", actor_user=self.request.user, device=device,
            safe_metadata={"device_label": device.device_label,
                           "owner_user_id": str(device.owner_user_id) if device.owner_user_id else None},
            strict=True,
        )


class DeviceDetailView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = DeviceSerializer
    lookup_field = "id"

    def get_queryset(self):
        qs = Device.objects.select_related("owner_user").all()
        return qs if self.request.user.is_admin else qs.filter(owner_user=self.request.user)


class DeviceStatusView(APIView):
    permission_classes = [IsAuthenticated, IsAdminRole]

    def post(self, request, id):
        serializer = DeviceStatusSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        device = change_device_status(id, serializer.validated_data["status"], request.user)
        return Response(DeviceSerializer(device).data)


class DeviceAssignmentView(APIView):
    permission_classes = [IsAuthenticated, IsAdminRole]

    def post(self, request, id):
        serializer = DeviceAssignmentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        device = assign_device(id, serializer.validated_data["owner_user"], request.user)
        return Response(DeviceSerializer(device).data, status=status.HTTP_200_OK)
