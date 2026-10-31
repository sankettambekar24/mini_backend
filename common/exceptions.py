"""
Custom exception handler.

Returns consistent JSON error shapes. Never leaks stack traces, SQL details,
secrets, internal paths, or token contents to the client.
"""

import uuid
import logging

from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status

logger = logging.getLogger("secure_backend.exceptions")


def custom_exception_handler(exc, context):
    """
    Returns:
        {
          "error": {
            "code": "SNAKE_CASE_CODE",
            "message": "Human-readable message.",
            "request_id": "<opaque-correlation-id>"
          }
        }
    """
    response = exception_handler(exc, context)
    request = context.get("request")
    request_id = getattr(request, "_request_id", str(uuid.uuid4()))

    if response is not None:
        detail = response.data

        # Normalise DRF's varied error shapes into one consistent shape.
        if isinstance(detail, dict) and "detail" in detail:
            message = str(detail["detail"])
            raw_code = detail.get("code") or getattr(detail["detail"], "code", "API_ERROR")
            code = str(raw_code).upper()
        elif isinstance(detail, list) and detail:
            message = str(detail[0])
            code = getattr(detail[0], "code", "VALIDATION_ERROR").upper()
        elif isinstance(detail, dict):
            message = "; ".join(
                f"{k}: {v[0] if isinstance(v, list) else v}"
                for k, v in detail.items()
            )
            code = "VALIDATION_ERROR"
        else:
            message = str(detail)
            code = "API_ERROR"

        response.data = {
            "error": {
                "code": code,
                "message": message,
                "request_id": request_id,
            }
        }
        return response

    # Unhandled exception — log safely and return a generic 500.
    logger.exception("Unhandled exception [request_id=%s]", request_id)
    return Response(
        {
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An unexpected error occurred. Please try again.",
                "request_id": request_id,
            }
        },
        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )
