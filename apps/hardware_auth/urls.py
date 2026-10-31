from django.urls import path
from apps.hardware_auth.views import (
    AuthAttemptCancelView,
    AuthAttemptCompleteView,
    AuthAttemptCreateView,
    AuthAttemptDetailView,
    AuthAttemptEventView,
)

urlpatterns = [
    path("", AuthAttemptCreateView.as_view(), name="auth-attempt-create"),
    path("<uuid:id>/", AuthAttemptDetailView.as_view(), name="auth-attempt-detail"),
    path("<uuid:id>/events/", AuthAttemptEventView.as_view(), name="auth-attempt-event"),
    path("<uuid:id>/complete/", AuthAttemptCompleteView.as_view(), name="auth-attempt-complete"),
    path("<uuid:id>/cancel/", AuthAttemptCancelView.as_view(), name="auth-attempt-cancel"),
]
