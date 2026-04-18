import json
from functools import lru_cache
from pathlib import Path
from typing import Any


PROMPT_DIR = Path(__file__).resolve().parents[1] / "prompts"


@lru_cache(maxsize=16)
def load_prompt_template(name: str) -> str:
    file_path = PROMPT_DIR / f"{name}.txt"
    return file_path.read_text(encoding="utf-8")


def _normalize(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=True, indent=2, default=str)


def render_prompt(name: str, **kwargs: Any) -> str:
    template = load_prompt_template(name)
    normalized = {key: _normalize(value) for key, value in kwargs.items()}
    return template.format(**normalized)
