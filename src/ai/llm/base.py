from abc import ABC, abstractmethod


class LLMProvider(ABC):
    @abstractmethod
    def complete(self, system: str, prompt: str, json_schema: dict | None = None) -> str:
        raise NotImplementedError


def get_provider(name: str = "ollama"):
    if name == "ollama":
        from .ollama_provider import OllamaProvider
        return OllamaProvider()
    if name == "api":
        from .api_provider import APIProvider
        return APIProvider()
    raise ValueError(f"unknown provider: {name}")
