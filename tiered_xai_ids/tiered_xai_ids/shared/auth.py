import os

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

_api_key_scheme = APIKeyHeader(name="X-Internal-Key", auto_error=False)


def require_internal_key(x_internal_key: str | None = Security(_api_key_scheme)) -> None:
    """FastAPI dependency that validates the inter-service API key.

    Apply to FL endpoints and /v1/reset so only authenticated internal
    services can submit model updates, sync weights, or wipe training data.

    If INTERNAL_API_KEY is empty or absent the check is skipped, which keeps
    development environments working without configuration.  Set a strong
    random value (e.g. ``openssl rand -hex 32``) in all production .env files.
    """
    expected = os.environ.get("INTERNAL_API_KEY", "")
    if not expected:
        return  # development mode — unenforced
    if not x_internal_key or x_internal_key != expected:
        raise HTTPException(status_code=403, detail="Invalid or missing internal API key")
