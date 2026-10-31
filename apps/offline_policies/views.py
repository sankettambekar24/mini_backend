from django.db import transaction
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.audit.services import record_audit_event
from apps.offline_policies.models import OfflinePolicy
from apps.offline_policies.serializers import OfflinePolicySerializer
from apps.offline_policies.services import (
    OfflinePolicyError,
    require_policy_issuance_enabled,
    revoke_policy,
)


def _error(code, http_status):
    return Response(
        {"error": {"code": code, "message": code.replace("_", " ").title()}},
        status=http_status,
    )


class OfflinePolicyListCreateView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = OfflinePolicySerializer

    def get_queryset(self):
        qs = OfflinePolicy.objects.prefetch_related("file_scopes").all()
        return qs if self.request.user.is_admin else qs.filter(user=self.request.user)

    @transaction.atomic
    def post(self, request):
        # Do not parse client grants or create a partial policy while the gate is shut.
        try:
            require_policy_issuance_enabled()
        except OfflinePolicyError:
            record_audit_event(
                "OFFLINE_POLICY_ISSUANCE_BLOCKED",
                "DENIED",
                actor_user=request.user,
                safe_metadata={"reason": "prerequisites_unavailable"},
                strict=True,
            )
            return _error("OFFLINE_POLICY_ISSUANCE_DISABLED", status.HTTP_503_SERVICE_UNAVAILABLE)
        # Phase A intentionally has no enabled issuance implementation.
        return _error("OFFLINE_POLICY_ISSUANCE_DISABLED", status.HTTP_503_SERVICE_UNAVAILABLE)


class OfflinePolicyDetailView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = OfflinePolicySerializer
    lookup_field = "id"

    def get_queryset(self):
        qs = OfflinePolicy.objects.prefetch_related("file_scopes").all()
        return qs if self.request.user.is_admin else qs.filter(user=self.request.user)


class OfflinePolicyRevokeView(APIView):
    permission_classes = [IsAuthenticated]

    @transaction.atomic
    def post(self, request, id):
        policy = OfflinePolicy.objects.filter(id=id).first()
        if policy is None:
            return _error("POLICY_NOT_FOUND", status.HTTP_404_NOT_FOUND)
        if not request.user.is_admin and policy.user_id != request.user.id:
            return _error("POLICY_NOT_FOUND", status.HTTP_404_NOT_FOUND)
        try:
            policy = revoke_policy(
                policy_id=id,
                actor=request.user,
                reason="OWNER_REQUEST" if policy.user_id == request.user.id else "ADMIN_REVOKED",
            )
        except OfflinePolicyError as exc:
            code = exc.code
            http_status = status.HTTP_404_NOT_FOUND if code == "POLICY_NOT_FOUND" else status.HTTP_409_CONFLICT
            return _error(code, http_status)
        return Response(OfflinePolicySerializer(policy).data)
