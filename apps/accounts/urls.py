from django.urls import path
from apps.accounts.views import MeView, RegisterView

urlpatterns = [
    path("auth/register/", RegisterView.as_view(), name="register"),
    path("auth/me/", MeView.as_view(), name="me"),
]
