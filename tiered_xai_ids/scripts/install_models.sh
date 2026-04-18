#!/usr/bin/env bash
set -euo pipefail

ROLE="${1:-all}"

if ! command -v ollama >/dev/null 2>&1; then
  echo "Ollama is not installed or not on PATH."
  exit 1
fi

if ! ollama list >/dev/null 2>&1; then
  echo "Starting Ollama service..."
  nohup ollama serve >/tmp/ollama-serve.log 2>&1 &
  sleep 3
fi

case "$ROLE" in
  laptop)
    MODELS=("mistral:7b" "qwen2.5:32b")
    ;;
  worker)
    MODELS=("phi3.5")
    ;;
  all)
    MODELS=("phi3.5" "mistral:7b" "qwen2.5:32b")
    ;;
  *)
    echo "Usage: $0 [all|laptop|worker]"
    exit 1
    ;;
esac

for model in "${MODELS[@]}"; do
  echo "Pulling model: $model"
  ollama pull "$model"
done

echo "Model install complete for role: $ROLE"
