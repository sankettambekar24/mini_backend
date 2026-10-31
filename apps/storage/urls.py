from django.urls import path

from apps.storage.views import (
    FileContentUnavailableView,
    FileDetailView,
    FileGrantListCreateView,
    FileGrantRevokeView,
    FileListView,
    FileMetadataCreateView,
)

urlpatterns = [
    path("", FileListView.as_view(), name="file-list"),
    path("metadata/", FileMetadataCreateView.as_view(), name="file-metadata-create"),
    path("<uuid:file_id>/", FileDetailView.as_view(), name="file-detail"),
    path("<uuid:file_id>/content/", FileContentUnavailableView.as_view(), name="file-content-unavailable"),
    path("<uuid:file_id>/grants/", FileGrantListCreateView.as_view(), name="file-grant-list-create"),
    path("<uuid:file_id>/grants/<uuid:grant_id>/revoke/", FileGrantRevokeView.as_view(), name="file-grant-revoke"),
]
