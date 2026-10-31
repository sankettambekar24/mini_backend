"""Versioned, metadata-only file and grant API.

There is intentionally no file-byte or upload handler in this phase. The
content endpoint authorizes the request, then reports that storage is not
available rather than consulting the legacy bridge or staged-file service.
"""

from django.http import Http404
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.permissions import IsAdminRole
from apps.permissions.models import PermissionGrant
from apps.storage.serializers import (
    FileGrantCreateSerializer,
    FileGrantSerializer,
    FileMetadataCreateSerializer,
    FileMetadataSerializer,
)
from apps.storage.services import (
    FileAuthorizationError,
    create_grant,
    get_file_for_content,
    get_file_for_grant_management,
    get_file_for_metadata,
    register_metadata,
    revoke_grant,
    visible_files,
)


def _error(code, http_status):
    return Response(
        {"error": {"code": code, "message": code.replace("_", " ").title()}},
        status=http_status,
    )


class FileListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = FileMetadataSerializer

    def get_queryset(self):
        return visible_files(self.request.user)


class FileMetadataCreateView(APIView):
    """Admin-only registration of metadata; it does not upload a file."""

    permission_classes = [IsAuthenticated, IsAdminRole]

    def post(self, request):
        serializer = FileMetadataCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        file_record = register_metadata(actor=request.user, **serializer.validated_data)
        return Response(FileMetadataSerializer(file_record).data, status=status.HTTP_201_CREATED)


class FileDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, file_id):
        file_record = get_file_for_metadata(file_id=file_id, user=request.user)
        return Response(FileMetadataSerializer(file_record).data)


class FileGrantListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, file_id):
        file_record = get_file_for_grant_management(file_id=file_id, user=request.user)
        # Grants are stored on their subject account, so query by the stable
        # file UUID. Only the owner or an administrator reaches this endpoint.
        grants = PermissionGrant.objects.filter(resource_id=str(file_record.id)).select_related(
            "subject_user", "granted_by"
        ).order_by("created_at", "id")
        return Response(FileGrantSerializer(grants, many=True).data)

    def post(self, request, file_id):
        serializer = FileGrantCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            grant = create_grant(file_id=file_id, actor=request.user, **serializer.validated_data)
        except Http404:
            raise
        except FileAuthorizationError as exc:
            return _error(exc.code, status.HTTP_409_CONFLICT)
        return Response(FileGrantSerializer(grant).data, status=status.HTTP_201_CREATED)


class FileGrantRevokeView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, file_id, grant_id):
        if request.data:
            return _error("REQUEST_BODY_NOT_ALLOWED", status.HTTP_400_BAD_REQUEST)
        try:
            grant = revoke_grant(file_id=file_id, grant_id=grant_id, actor=request.user)
        except Http404:
            raise
        except FileAuthorizationError as exc:
            return _error(exc.code, status.HTTP_409_CONFLICT)
        return Response(FileGrantSerializer(grant).data)


class FileContentUnavailableView(APIView):
    """Fail-closed placeholder; no physical or staged bytes are returned."""

    permission_classes = [IsAuthenticated]

    def get(self, request, file_id):
        get_file_for_content(file_id=file_id, user=request.user)
        return _error("FILE_CONTENT_UNAVAILABLE", status.HTTP_503_SERVICE_UNAVAILABLE)
