import re

# Patterns that commonly appear in prompt-injection payloads.
# Each tuple is (compiled pattern, replacement text).
_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?"), "[REDACTED]"),
    (re.compile(r"(?i)forget\s+(?:all\s+)?(?:previous|prior|above)"), "[REDACTED]"),
    (re.compile(r"(?i)you\s+are\s+now\s+(?:a\s+)?(?:different|new|an?\s+)"), "[REDACTED]"),
    (re.compile(r"(?i)<\s*/?\s*(?:system|prompt|instruction|context|human|assistant)\s*>"), "[REDACTED]"),
    (re.compile(r"(?i)\[\s*(?:INST|SYSTEM|INSTRUCTION)\s*\]"), "[REDACTED]"),
    (re.compile(r"(?i)###\s*(?:system|instruction|human|assistant|prompt)\b"), "[REDACTED]"),
    (re.compile(r"(?i)---\s*system\s*---"), "[REDACTED]"),
    (re.compile(r"(?i)print\s+(?:the\s+)?(?:system\s+)?prompt"), "[REDACTED]"),
    (re.compile(r"(?i)reveal\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)"), "[REDACTED]"),
    (re.compile(r"(?i)act\s+as\s+(?:if\s+)?(?:you\s+(?:are|were)\s+)?(?:a\s+)?(?:different|new|unrestricted)"), "[REDACTED]"),
    (re.compile(r"(?i)disregard\s+(?:all\s+)?(?:previous|prior|above)"), "[REDACTED]"),
    (re.compile(r"(?i)override\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)"), "[REDACTED]"),
]


def sanitize_for_llm(text: str, max_length: int = 3000) -> str:
    """Sanitize raw log text before embedding it in an LLM prompt.

    Two layers of protection:
    1. Redacts known prompt-injection trigger phrases with [REDACTED].
    2. Wraps the result in DATA_START/DATA_END fences so the LLM system
       prompt can explicitly instruct the model to treat the fenced content
       as verbatim data, not executable instructions.

    The max_length truncation happens before redaction so injected payloads
    cannot use padding to push real content past the check window.
    """
    truncated = text[:max_length]
    sanitized = truncated
    for pattern, replacement in _INJECTION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return f"[DATA_START]\n{sanitized}\n[DATA_END]"
