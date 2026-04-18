import asyncio
import json
import logging
from typing import TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from tiered_xai_ids.shared.correlation import build_outbound_headers


logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class OllamaClientError(Exception):
    """Raised when the Ollama API call fails."""


class OllamaResponseFormatError(OllamaClientError):
    """Raised when a model repeatedly returns invalid JSON."""


class OllamaClient:
    def __init__(self, base_url: str, timeout_seconds: float, max_retries: int = 3) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.max_retries = max(1, max_retries)

    async def check_health(self) -> bool:
        url = f"{self.base_url}/api/tags"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.get(url, headers=build_outbound_headers())
                response.raise_for_status()
            return True
        except Exception:
            return False

    async def chat_json(
        self,
        *,
        model: str,
        system_prompt: str,
        user_prompt: str,
        response_model: type[T],
        temperature: float = 0.0,
    ) -> T:
        url = f"{self.base_url}/api/chat"
        payload = {
            "model": model,
            "stream": False,
            "format": response_model.model_json_schema(),
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "options": {"temperature": temperature},
        }

        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                    response = await client.post(url, json=payload, headers=build_outbound_headers())
                    response.raise_for_status()
                    data = response.json()

                content = self._extract_content(data)
                parsed = self._extract_json_payload(content)
                return response_model.model_validate(parsed)
            except (ValidationError, json.JSONDecodeError, KeyError, TypeError) as exc:
                last_error = exc
                logger.warning("invalid_model_json attempt=%s error=%s", attempt, str(exc))
            except httpx.HTTPError as exc:
                last_error = exc
                logger.error("ollama_http_error attempt=%s error=%s", attempt, str(exc))
            if attempt < self.max_retries:
                await asyncio.sleep(0.35 * attempt)

        raise OllamaResponseFormatError(
            f"Model returned invalid JSON after {self.max_retries} attempts: {last_error}"
        )

    @staticmethod
    def _extract_content(response_data: dict) -> str:
        message = response_data.get("message", {})
        content = message.get("content", "")
        if not isinstance(content, str):
            raise TypeError("Ollama response message.content is not a string")
        return content.strip()

    @staticmethod
    def _extract_json_payload(content: str) -> dict:
        if not content:
            raise json.JSONDecodeError("Empty content", doc="", pos=0)
        try:
            parsed = json.loads(content)
            if not isinstance(parsed, dict):
                raise TypeError("Expected JSON object")
            return parsed
        except Exception:
            start = content.find("{")
            end = content.rfind("}")
            if start == -1 or end == -1 or end <= start:
                raise json.JSONDecodeError("No JSON object found", content, 0)
            candidate = content[start : end + 1]
            parsed = json.loads(candidate)
            if not isinstance(parsed, dict):
                raise TypeError("Expected JSON object")
            return parsed
