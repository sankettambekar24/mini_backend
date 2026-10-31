from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from apps.accounts.permissions import IsAdminRole
from apps.audit.models import AuditEvent
from apps.audit.serializers import AuditEventSerializer


class AuditEventListView(generics.ListAPIView):
    """GET /api/v1/audit/events/ — admin-only, paginated."""

    permission_classes = [IsAuthenticated, IsAdminRole]
    serializer_class = AuditEventSerializer

    def get_queryset(self):
        qs = AuditEvent.objects.select_related("actor_user").order_by("-occurred_at")
        event_type = self.request.query_params.get("event_type")
        if event_type:
            qs = qs.filter(event_type=event_type)
        return qs


class AuditEventDetailView(generics.RetrieveAPIView):
    """GET /api/v1/audit/events/{event_id}/ — admin-only."""

    permission_classes = [IsAuthenticated, IsAdminRole]
    serializer_class = AuditEventSerializer
    queryset = AuditEvent.objects.all()
    lookup_field = "id"
