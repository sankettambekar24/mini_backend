from django.urls import path
from apps.audit.views import AuditEventListView, AuditEventDetailView

urlpatterns = [
    path("events/", AuditEventListView.as_view(), name="audit-events-list"),
    path("events/<uuid:id>/", AuditEventDetailView.as_view(), name="audit-events-detail"),
]
