"""
api_provider.py  —  Person 1

STUB. Not used in the MVP (no paid API). Exists so the seam is visible:
later, drop in Anthropic/OpenAI here and set provider="api". Zero changes
needed anywhere else in the pipeline.
"""

from .base import LLMProvider


class APIProvider(LLMProvider):
    def complete(self, system: str, prompt: str, json_schema=None) -> str:
        raise NotImplementedError(
            "API provider is a future extension. MVP uses local Ollama."
        )
