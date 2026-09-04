"""
base.py  —  Person 1

The LLM provider interface. Everything else calls .complete() and never
knows or cares whether it's talking to Ollama (now) or an API (later).
"""

from abc import ABC, abstractmethod


class LLMProvider(ABC):
    @abstractmethod
    def complete(self, system: str, prompt: str, json_schema: dict | None = None) -> str:
        """
        Send a prompt, return the model's text response.
        If json_schema is given, ask the model to return JSON matching it.
        """
        raise NotImplementedError


def get_provider(name: str = "ollama"):
    """Pick a provider by name. Default = local Ollama, no paid API."""
    if name == "ollama":
        from .ollama_provider import OllamaProvider
        return OllamaProvider()
    if name == "api":
        from .api_provider import APIProvider
        return APIProvider()
    raise ValueError(f"unknown provider: {name}")
