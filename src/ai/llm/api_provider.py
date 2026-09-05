from .base import LLMProvider


class APIProvider(LLMProvider):
    def complete(self, system: str, prompt: str, json_schema=None) -> str:
        raise NotImplementedError("API provider not configured.")
