from typing import Any

import httpx

from tiered_xai_ids.shared.correlation import build_outbound_headers


async def post_json(url: str, payload: dict[str, Any], timeout_seconds: float) -> tuple[int, dict[str, Any]]:
    async with httpx.AsyncClient(timeout=timeout_seconds) as client:
        response = await client.post(url, json=payload, headers=build_outbound_headers())
        response.raise_for_status()
        data = response.json()
    if not isinstance(data, dict):
        raise TypeError("Expected JSON object response")
    return response.status_code, data


async def get_json(url: str, timeout_seconds: float) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=timeout_seconds) as client:
        response = await client.get(url, headers=build_outbound_headers())
        response.raise_for_status()
        data = response.json()
    if not isinstance(data, dict):
        raise TypeError("Expected JSON object response")
    return data
