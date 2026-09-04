"""
ollama_provider.py  

Talks to a local Ollama server. Free, offline, no API key.
Start Ollama and pull the model first:
    ollama pull llama3.1

If JSON adherence is bad, switch MODEL to "qwen3:7b" (better at JSON) —
this one line is the only change needed.
"""

import json
import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.1"


class OllamaProvider:
    def __init__(self, model: str = MODEL, url: str = OLLAMA_URL):
        self.model = model
        self.url = url

    def complete(self, system: str, prompt: str, json_schema: dict | None = None) -> str:
        payload = {
            "model": self.model,
            "system": system,
            "prompt": prompt,
            "stream": False,
        }
        # Ollama can constrain output to JSON. "json" forces valid JSON;
        # passing the schema dict constrains to that shape (newer Ollama).
        if json_schema is not None:
            payload["format"] = json_schema if isinstance(json_schema, dict) else "json"

        resp = requests.post(self.url, json=payload, timeout=180)
        resp.raise_for_status()
        return resp.json()["response"]


if __name__ == "__main__":
    # quick smoke test — run this FIRST, before writing any other code
    p = OllamaProvider()
    print(p.complete("You are terse.", "Say hello in one word."))
