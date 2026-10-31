"""
Health check endpoints.
These endpoints must never expose secrets, stack traces, or internal details.
- /live/ : simple process liveness (no DB call)
- /ready/ : checks database connectivity safely
"""

import uuid

from django.core.cache import cache
from django.db import connection
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView


class LivenessView(APIView):
    """GET /api/v1/health/live/ — process is alive. No secrets, no DB."""

    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_classes = []

    def get(self, request):
        return Response({"status": "ok", "service": "hybrid-secure-storage-backend"})


class ReadinessView(APIView):
    """GET /api/v1/health/ready/ — database and shared throttle cache are reachable."""

    permission_classes = [AllowAny]
    authentication_classes = []
    # Health must remain observable when Redis (also used by DRF throttles) is down.
    throttle_classes = []

    def get(self, request):
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            db_ok = True
        except Exception:
            db_ok = False

        cache_ok = False
        cache_key = f"health:ready:{uuid.uuid4()}"
        cache_value = str(uuid.uuid4())
        try:
            cache.set(cache_key, cache_value, timeout=5)
            cache_ok = cache.get(cache_key) == cache_value
            cache.delete(cache_key)
        except Exception:
            cache_ok = False

        status_code = 200 if db_ok and cache_ok else 503
        healthy = status_code == 200
        return Response(
            {
                "status": "ok" if healthy else "degraded",
                "database": "ok" if db_ok else "unavailable",
                "cache": "ok" if cache_ok else "unavailable",
            },
            status=status_code,
        )
