from django.urls import path

from apps.offline_policies.views import (
    OfflinePolicyDetailView,
    OfflinePolicyListCreateView,
    OfflinePolicyRevokeView,
)

urlpatterns = [
    path("", OfflinePolicyListCreateView.as_view(), name="offline-policy-list-create"),
    path("<uuid:id>/", OfflinePolicyDetailView.as_view(), name="offline-policy-detail"),
    path("<uuid:id>/revoke/", OfflinePolicyRevokeView.as_view(), name="offline-policy-revoke"),
]
