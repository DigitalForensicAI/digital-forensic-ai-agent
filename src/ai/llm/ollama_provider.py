import json
import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.2:latest"


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
        if json_schema is not None:
            payload["format"] = json_schema if isinstance(json_schema, dict) else "json"

        resp = requests.post(self.url, json=payload, timeout=180)
        
        resp.raise_for_status()
        return resp.json()["response"]


if __name__ == "__main__":
    # quick smoke test — run this FIRST, before writing any other code
    p = OllamaProvider()
    print(p.complete("You are terse.", "Say hello in one word."))
