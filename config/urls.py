"""URL configuration for the Hybrid Secure Storage System backend."""

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/health/", include("apps.health.urls")),
    path("api/v1/auth/", include("apps.authentication.urls")),
    path("api/v1/", include("apps.accounts.urls")),
    path("api/v1/devices/", include("apps.devices.urls")),
    path("api/v1/auth-attempts/", include("apps.hardware_auth.urls")),
    path("api/v1/files/", include("apps.storage.urls")),
    path("api/v1/offline-policies/", include("apps.offline_policies.urls")),
    path("api/v1/audit/", include("apps.audit.urls")),
    path("api/v1/admin/", include("apps.accounts.admin_urls")),
]
