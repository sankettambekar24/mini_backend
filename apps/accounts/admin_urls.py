from django.urls import path
from apps.accounts.views import (
    AdminUserDisableView,
    AdminUserListCreateView,
    AdminUserDetailView,
    AdminUserRoleView,
)

urlpatterns = [
    path("users/", AdminUserListCreateView.as_view(), name="admin-users-list"),
    path("users/<uuid:id>/", AdminUserDetailView.as_view(), name="admin-users-detail"),
    path("users/<uuid:id>/disable/", AdminUserDisableView.as_view(), name="admin-users-disable"),
    path("users/<uuid:id>/role/", AdminUserRoleView.as_view(), name="admin-users-role"),
]
