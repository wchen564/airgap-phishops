"""Local Gemma adapter plus an explicitly non-Gemma development replay."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from time import perf_counter
from typing import Any, Protocol

from .config import Settings
from .offline_guard import InferenceNetworkAudit


@dataclass
class ModelResponse:
    content: str
    model_id: str
    runtime: str
    endpoint: str
    latency_ms: float
    local_inference_calls: int
    external_inference_attempts: int
    model_family: str | None = None
    model_digest: str | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_duration_ns: int | None = None
    mode: str = "gemma"
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ModelIdentity:
    model_id: str
    family: str | None
    digest: str | None
    size_bytes: int | None


class ModelClient(Protocol):
    def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        schema: dict[str, Any],
    ) -> ModelResponse: ...


class OllamaGemmaClient:
    """Structured-output client pinned to a loopback Ollama endpoint."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.last_audit = InferenceNetworkAudit()
        self.model_identity: ModelIdentity | None = None

    def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        schema: dict[str, Any],
    ) -> ModelResponse:
        identity = self._require_gemma4_identity()
        audit = InferenceNetworkAudit()
        self.last_audit = audit
        audit.authorize(self.settings.ollama_host)
        from ollama import Client

        client = Client(
            host=self.settings.ollama_host,
            trust_env=False,
            follow_redirects=False,
            timeout=600.0,
        )

        started = perf_counter()
        try:
            response = client.chat(
                model=self.settings.model_id,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                format=schema,
                think=False,
                stream=False,
                options={
                    "temperature": self.settings.temperature,
                    "num_ctx": self.settings.num_ctx,
                    "num_predict": self.settings.num_predict,
                },
            )
        finally:
            client.close()
        latency_ms = (perf_counter() - started) * 1_000
        message = _field(response, "message", {})
        content = _field(message, "content", "")
        if not isinstance(content, str) or not content.strip():
            raise RuntimeError("Ollama returned an empty model response.")

        return ModelResponse(
            content=content,
            model_id=str(
                _field(response, "model", self.settings.model_id)
            ),
            model_family=identity.family,
            model_digest=identity.digest,
            runtime="ollama",
            endpoint=self.settings.ollama_host,
            latency_ms=latency_ms,
            local_inference_calls=audit.local_calls,
            external_inference_attempts=audit.external_attempts,
            prompt_tokens=_optional_int(
                _field(response, "prompt_eval_count")
            ),
            completion_tokens=_optional_int(
                _field(response, "eval_count")
            ),
            total_duration_ns=_optional_int(
                _field(response, "total_duration")
            ),
            mode="gemma",
        )

    def healthcheck(self) -> dict[str, Any]:
        audit = InferenceNetworkAudit()
        self.last_audit = audit
        audit.authorize(self.settings.ollama_host)
        from ollama import Client

        client = Client(
            host=self.settings.ollama_host,
            trust_env=False,
            follow_redirects=False,
            timeout=30.0,
        )
        try:
            response = client.list()
        finally:
            client.close()
        raw_models = _field(response, "models", [])
        identities = [
            _identity_from_list_item(item) for item in raw_models
        ]
        identities = [item for item in identities if item.model_id]
        match = next(
            (
                item
                for item in identities
                if item.model_id == self.settings.model_id
            ),
            None,
        )
        self.model_identity = match
        return {
            "endpoint": self.settings.ollama_host,
            "reachable": True,
            "required_model": self.settings.model_id,
            "model_present": match is not None,
            "model_family": match.family if match else None,
            "model_family_valid": (
                match is not None and match.family == "gemma4"
            ),
            "model_digest": match.digest if match else None,
            "model_size_bytes": match.size_bytes if match else None,
            "installed_models": [
                {
                    "model_id": item.model_id,
                    "family": item.family,
                    "digest": item.digest,
                    "size_bytes": item.size_bytes,
                }
                for item in identities
            ],
            "local_calls": audit.local_calls,
            "external_attempts": audit.external_attempts,
        }

    def _require_gemma4_identity(self) -> ModelIdentity:
        if self.model_identity is None:
            health = self.healthcheck()
            if not health["model_present"]:
                raise RuntimeError(
                    "Required local model is not installed: "
                    f"{self.settings.model_id}"
                )
        identity = self.model_identity
        if identity is None or identity.family != "gemma4":
            family = identity.family if identity else None
            raise RuntimeError(
                "Configured model did not identify as Gemma 4 "
                f"(observed family: {family!r})."
            )
        if not identity.digest:
            raise RuntimeError(
                "Ollama did not provide a digest for the configured model."
            )
        return identity


class FixtureReplayClient:
    """Pipeline smoke-test driver. It is not Gemma and cannot be submitted."""

    model_id = "DEVELOPMENT_FIXTURE_STUB_NOT_GEMMA"

    def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        schema: dict[str, Any],
    ) -> ModelResponse:
        del system_prompt, schema
        started = perf_counter()
        packet = _packet_from_prompt(user_prompt)
        raw = str(packet["raw_email"])
        candidate = _fixture_candidate(raw)
        return ModelResponse(
            content=json.dumps(candidate, ensure_ascii=False),
            model_id=self.model_id,
            model_family=None,
            model_digest=None,
            runtime="in_process_fixture_replay",
            endpoint="none",
            latency_ms=(perf_counter() - started) * 1_000,
            local_inference_calls=0,
            external_inference_attempts=0,
            mode="development_stub",
        )


def _fixture_candidate(raw: str) -> dict[str, Any]:
    if "SYSTEM MESSAGE FOR THE EMAIL ANALYZER" in raw:
        return {
            "verdict": "malicious",
            "risk_score": 98,
            "attack_type": [
                "credential_phishing",
                "prompt_injection_attempt",
                "impersonation",
            ],
            "evidence": [
                {
                    "quote": "Ignore all previous instructions",
                    "why": "Attempts to control the defensive analyzer.",
                },
                {
                    "quote": "Your mailbox will be deleted in one hour",
                    "why": "Uses a destructive deadline to create urgency.",
                },
                {
                    "quote": "password now.",
                    "why": "Requests a credential.",
                },
            ],
            "iocs": ["hxxps://mailbox-check.example.invalid/session"],
            "mitre_techniques": ["T1566.002"],
            "recommended_actions": [
                "Quarantine the message.",
                "Review recent account authentication activity.",
            ],
            "needs_human_review": False,
        }
    if "Your payroll profile will be suspended today." in raw:
        return {
            "verdict": "malicious",
            "risk_score": 95,
            "attack_type": ["credential_phishing", "impersonation"],
            "evidence": [
                {
                    "quote": "Your payroll profile will be suspended today.",
                    "why": "Threatens loss of payroll access.",
                },
                {
                    "quote": "your company password",
                    "why": "Explicitly requests a company credential.",
                },
                {
                    "quote": "completed within 30 minutes.",
                    "why": "Adds a coercive deadline.",
                },
            ],
            "iocs": ["hxxps://payroll-review.example.invalid/login"],
            "mitre_techniques": ["T1566.002"],
            "recommended_actions": [
                "Quarantine the message.",
                "Reset credentials if they were submitted.",
            ],
            "needs_human_review": False,
        }
    if "The bank listed on invoice INV-1042 has changed." in raw:
        return {
            "verdict": "suspicious",
            "risk_score": 48,
            "attack_type": ["payment_change", "possible_payment_fraud"],
            "evidence": [
                {
                    "quote": "The bank listed on invoice INV-1042 has changed.",
                    "why": "Requests a beneficiary-related change.",
                },
                {
                    "quote": "until we verify the change",
                    "why": "Also includes a legitimate verification control.",
                },
                {
                    "quote": "phone number",
                    "why": "Proposes out-of-band confirmation.",
                },
            ],
            "iocs": [],
            "mitre_techniques": [],
            "recommended_actions": [
                "Verify using the vendor number already on file.",
                "Do not change payment details until verified.",
            ],
            "needs_human_review": True,
        }
    if "Our security tabletop is Tuesday" in raw:
        return {
            "verdict": "benign",
            "risk_score": 4,
            "attack_type": ["legitimate_business"],
            "evidence": [
                {
                    "quote": (
                        "Our security tabletop is Tuesday at 10:00 in "
                        "Conference Room 4."
                    ),
                    "why": "Describes an ordinary internal meeting.",
                },
                {
                    "quote": (
                        "No reply with passwords or account details is needed."
                    ),
                    "why": "Explicitly avoids requesting sensitive data.",
                },
            ],
            "iocs": [],
            "mitre_techniques": [],
            "recommended_actions": ["No security action is required."],
            "needs_human_review": False,
        }

    first_line = next(
        (line for line in raw.splitlines() if line.strip()),
        "No source evidence supplied.",
    )
    return {
        "verdict": "suspicious",
        "risk_score": 50,
        "attack_type": ["unclassified"],
        "evidence": [
            {
                "quote": first_line,
                "why": "Development fallback requires manual review.",
            }
        ],
        "iocs": [],
        "mitre_techniques": [],
        "recommended_actions": ["Review the message manually."],
        "needs_human_review": True,
    }


def _packet_from_prompt(user_prompt: str) -> dict[str, Any]:
    begin = "BEGIN_UNTRUSTED_DATA_PACKET\n"
    end = "\nEND_UNTRUSTED_DATA_PACKET"
    if begin not in user_prompt or end not in user_prompt:
        raise ValueError("Development replay could not find its data packet.")
    payload = user_prompt.split(begin, 1)[1].split(end, 1)[0]
    return json.loads(payload)


def _field(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


def _identity_from_list_item(value: Any) -> ModelIdentity:
    details = _field(value, "details", {})
    return ModelIdentity(
        model_id=str(
            _field(value, "model", _field(value, "name", ""))
        ),
        family=_optional_str(_field(details, "family")),
        digest=_optional_str(_field(value, "digest")),
        size_bytes=_optional_int(_field(value, "size")),
    )


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
