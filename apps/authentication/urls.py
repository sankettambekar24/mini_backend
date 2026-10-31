from django.urls import path
from apps.authentication.views import (
    ChangePasswordView,
    LoginView,
    LogoutView,
    OfflinePreAuthAttemptView,
    TokenRefreshViewAudited,
)

urlpatterns = [
    path("preauth/", OfflinePreAuthAttemptView.as_view(), name="offline-preauth-attempt"),
    path("token/", LoginView.as_view(), name="token-obtain"),
    path("token/refresh/", TokenRefreshViewAudited.as_view(), name="token-refresh"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("change-password/", ChangePasswordView.as_view(), name="change-password"),
]
