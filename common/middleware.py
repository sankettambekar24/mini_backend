"""
Request ID middleware.

Attaches a unique correlation ID to every request so it can be included
in error responses and structured logs without exposing sensitive data.
"""

import uuid


class RequestIDMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request._request_id = str(uuid.uuid4())
        response = self.get_response(request)
        response["X-Request-ID"] = request._request_id
        return response
