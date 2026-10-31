from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.permissions import IsAdminRole
from apps.authentication.authentication import AttemptCapabilityAuthentication, SecureJWTAuthentication
from apps.hardware_auth.models import AuthAttempt, AuthAttemptCapability
from apps.hardware_auth.serializers import (
    AttemptBindingSerializer,
    AuthAttemptCreateSerializer,
    AuthAttemptSerializer,
    FactorReportSerializer,
)
from apps.hardware_auth.services import cancel_attempt, complete_attempt, create_attempt, report_factor


ERROR_STATUS = {
    "ATTEMPT_NOT_FOUND": status.HTTP_404_NOT_FOUND,
    "DEVICE_NOT_FOUND": status.HTTP_404_NOT_FOUND,
    "ATTEMPT_USER_MISMATCH": status.HTTP_403_FORBIDDEN,
    "ATTEMPT_DEVICE_MISMATCH": status.HTTP_403_FORBIDDEN,
    "ATTEMPT_BINDING_MISMATCH": status.HTTP_403_FORBIDDEN,
    "DEVICE_USER_MISMATCH": status.HTTP_403_FORBIDDEN,
    "DEVICE_INACTIVE": status.HTTP_403_FORBIDDEN,
    "USER_INACTIVE": status.HTTP_403_FORBIDDEN,
    "ATTEMPT_EXPIRED": status.HTTP_410_GONE,
}


def error_response(code):
    return Response({"error": {"code": code, "message": code.replace("_", " ").title()}},
                    status=ERROR_STATUS.get(code, status.HTTP_409_CONFLICT))


class AuthAttemptCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = AuthAttemptCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        attempt, error = create_attempt(user=request.user, **serializer.validated_data)
        if error:
            return error_response(error)
        return Response(AuthAttemptSerializer(attempt).data, status=status.HTTP_201_CREATED)


class AuthAttemptDetailView(generics.RetrieveAPIView):
    authentication_classes = [SecureJWTAuthentication, AttemptCapabilityAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = AuthAttemptSerializer
    lookup_field = "id"

    def get_queryset(self):
        qs = AuthAttempt.objects.prefetch_related("events").all()
        if isinstance(self.request.auth, AuthAttemptCapability):
            return qs.filter(id=self.request.auth.attempt_id)
        return qs if self.request.user.is_admin else qs.filter(user=self.request.user)


class AuthAttemptEventView(APIView):
    authentication_classes = [SecureJWTAuthentication, AttemptCapabilityAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, id):
        serializer = FactorReportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        values = serializer.validated_data
        attempt, event, error = report_factor(
            attempt_id=id,
            actor=request.user,
            device_id=values["device_id"],
            event_id=values["event_id"],
            factor=values["factor"],
            protocol_version=values["contract_version"],
        )
        if error:
            return error_response(error)
        response = AuthAttemptSerializer(attempt).data
        response["reported_event"] = {
            "id": str(event.id), "event_id": str(event.event_id), "factor": event.factor,
            "evidence_class": event.evidence_class, "verified": False,
        }
        return Response(response, status=status.HTTP_201_CREATED)


class AuthAttemptCancelView(APIView):
    authentication_classes = [SecureJWTAuthentication, AttemptCapabilityAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, id):
        serializer = AttemptBindingSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        attempt, error = cancel_attempt(attempt_id=id, actor=request.user, **serializer.validated_data)
        if error:
            return error_response(error)
        return Response(AuthAttemptSerializer(attempt).data)


class AuthAttemptCompleteView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, id):
        serializer = AttemptBindingSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        attempt, error = complete_attempt(attempt_id=id, actor=request.user, **serializer.validated_data)
        if error:
            return error_response(error)
        return Response(AuthAttemptSerializer(attempt).data)
