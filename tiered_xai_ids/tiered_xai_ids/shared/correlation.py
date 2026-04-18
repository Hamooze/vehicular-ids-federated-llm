import os
from contextvars import ContextVar, Token
from uuid import uuid4

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware


CORRELATION_HEADER = "X-Correlation-ID"
INTERNAL_KEY_HEADER = "X-Internal-Key"
_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="-")


def get_correlation_id() -> str:
    return _correlation_id.get()


def set_correlation_id(value: str) -> Token[str]:
    return _correlation_id.set(value)


def build_outbound_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Build headers for inter-service HTTP calls.

    Propagates the correlation ID and, when INTERNAL_API_KEY is configured,
    the internal service key so that protected endpoints can verify the caller.
    """
    headers: dict[str, str] = {CORRELATION_HEADER: get_correlation_id()}
    key = os.environ.get("INTERNAL_API_KEY", "")
    if key:
        headers[INTERNAL_KEY_HEADER] = key
    if extra:
        headers.update(extra)
    return headers


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        correlation_id = request.headers.get(CORRELATION_HEADER, str(uuid4()))
        token = set_correlation_id(correlation_id)
        try:
            response = await call_next(request)
        finally:
            _correlation_id.reset(token)

        response.headers[CORRELATION_HEADER] = correlation_id
        return response
