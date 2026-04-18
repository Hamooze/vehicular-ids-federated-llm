import json
import os
from typing import Optional

from gpt4all import GPT4All


DEFAULT_MODEL_NAME = "phi-2.Q4_K_M.gguf"
DEFAULT_MODEL_DIR = os.path.join("models", "phi2")


class SystemAIAgent:
    """
    Lightweight wrapper around GPT4All local models so we can provide
    contextual operator updates without leaving the machine.
    """

    def __init__(self, model_name: str = DEFAULT_MODEL_NAME, model_dir: str = DEFAULT_MODEL_DIR):
        self.model_name = model_name
        self.model_dir = model_dir
        os.makedirs(self.model_dir, exist_ok=True)

        self.model: Optional[GPT4All] = None
        self._load_model()

    def _load_model(self):
        model_file = os.path.join(self.model_dir, self.model_name)
        if not os.path.isfile(model_file):
            print(
                f"[LLM] Model file '{model_file}' not found. "
                "Place the GGUF file locally; online downloads are disabled."
            )
            self.model = None
            return

        try:
            self.model = GPT4All(
                self.model_name,
                model_path=self.model_dir,
                allow_download=False  # Prevent network calls; require local models
            )
        except Exception as exc:
            print(f"[LLM] Failed to load GPT4All model {self.model_name}: {exc}")
            self.model = None

    @property
    def available(self) -> bool:
        return self.model is not None

    def _compose_prompt(self, user_message: str, telemetry: dict) -> str:
        summary = json.dumps(telemetry, indent=2)
        return (
            "You are the SVN Guardian, an on-premise AI operator for a smart vehicular network. "
            "You speak in short, confident sentences, always referencing concrete metrics when possible. "
            "If data is unavailable, acknowledge that politely instead of fabricating values.\n\n"
            f"Current Telemetry:\n{summary}\n\n"
            f"Operator Message: {user_message}\n\n"
            "Assistant Response:"
        )

    def respond(self, user_message: str, telemetry: dict) -> str:
        if not user_message:
            return "I need a question or command to respond to."

        if not self.available:
            return (
                "The onboard LLM is offline. Please ensure the GPT4All model files are present "
                "inside the models/gpt4all directory."
            )

        prompt = self._compose_prompt(user_message, telemetry)
        try:
            output = self.model.generate(
                prompt,
                max_tokens=256,
                temp=0.4,
                top_p=0.9,
                repeat_penalty=1.1,
            )
            return output.strip()
        except Exception as exc:
            return f"LLM inference error: {exc}"
