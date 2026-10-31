from django.urls import path
from apps.devices.views import DeviceAssignmentView, DeviceDetailView, DeviceListCreateView, DeviceStatusView

urlpatterns = [
    path("", DeviceListCreateView.as_view(), name="device-list-create"),
    path("<uuid:id>/", DeviceDetailView.as_view(), name="device-detail"),
    path("<uuid:id>/status/", DeviceStatusView.as_view(), name="device-status"),
    path("<uuid:id>/assign/", DeviceAssignmentView.as_view(), name="device-assign"),
]
