"""Runtime configuration loaded from environment variables."""

from __future__ import annotations

from dataclasses import dataclass
import os


def _positive_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    value = int(raw)
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


@dataclass(frozen=True)
class Settings:
    """Settings chosen for a 16 GB Apple-silicon competition laptop."""

    model_id: str = "gemma4:e4b-it-qat"
    ollama_host: str = "http://127.0.0.1:11434"
    num_ctx: int = 8192
    num_predict: int = 768
    max_email_chars: int = 12_000
    temperature: float = 0.0

    def __post_init__(self) -> None:
        if not self.model_id.startswith("gemma4:"):
            raise ValueError(
                "GEMMA_MODEL must be an explicit Gemma 4 tag "
                "(for example gemma4:e4b-it-qat)."
            )

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            model_id=os.getenv("GEMMA_MODEL", cls.model_id),
            ollama_host=os.getenv("OLLAMA_HOST", cls.ollama_host),
            num_ctx=_positive_int("GEMMA_NUM_CTX", cls.num_ctx),
            num_predict=_positive_int(
                "GEMMA_NUM_PREDICT", cls.num_predict
            ),
            max_email_chars=_positive_int(
                "MAX_EMAIL_CHARS", cls.max_email_chars
            ),
        )
