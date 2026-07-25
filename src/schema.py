"""Pydantic contracts for model output and the validated report."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
)


Verdict = Literal["benign", "suspicious", "malicious"]
MitreTechnique = Literal[
    "T1566",
    "T1566.001",
    "T1566.002",
    "T1566.003",
    "T1204.001",
    "T1204.002",
    "T1056.003",
    "T1078",
]
AttackLabel = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=2,
        max_length=64,
        pattern=r"^[a-z0-9]+(?:_[a-z0-9]+)*$",
    ),
]
ShortText = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=3,
        max_length=500,
    ),
]
ObservableString = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=3,
        max_length=1_000,
    ),
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Evidence(StrictModel):
    quote: str = Field(
        min_length=3,
        max_length=1_000,
        description="An exact, case-sensitive substring from the raw email.",
    )
    why: ShortText = Field(
        description="Why this exact quote matters to the verdict.",
    )

    @field_validator("quote")
    @classmethod
    def quote_must_contain_visible_text(cls, value: str) -> str:
        if len(value.strip()) < 3:
            raise ValueError(
                "Evidence quotes need at least three visible characters."
            )
        return value


class Signal(StrictModel):
    kind: Literal[
        "urgency",
        "credential_request",
        "payment_change",
        "prompt_injection",
        "sensitive_data_request",
    ]
    quote: str


class UrlObservation(StrictModel):
    original: str
    host: str | None = None
    is_defanged: bool = False
    host_is_ip: bool = False
    contains_at_symbol: bool = False
    uses_punycode: bool = False
    excessive_subdomains: bool = False
    syntax_error: str | None = None


class ToolObservations(StrictModel):
    headers: dict[str, str | None]
    email_addresses: list[str]
    urls: list[str]
    ip_addresses: list[str]
    url_features: list[UrlObservation]
    signals: list[Signal]
    header_anomalies: list[str]
    truncated_fields: list[str] = Field(default_factory=list)


class ModelAnalysis(StrictModel):
    """The only schema Gemma is allowed to produce."""

    verdict: Verdict
    risk_score: int = Field(ge=0, le=100)
    attack_type: list[AttackLabel] = Field(
        max_length=8,
        description=(
            "Short snake_case labels such as credential_phishing, "
            "business_email_compromise, payment_fraud, impersonation, "
            "malware_delivery, prompt_injection_attempt, or "
            "legitimate_business."
        ),
    )
    evidence: list[Evidence] = Field(max_length=12)
    iocs: list[ObservableString] = Field(
        max_length=30,
        description="Only observable strings copied from the raw email.",
    )
    mitre_techniques: list[MitreTechnique] = Field(max_length=8)
    recommended_actions: list[ShortText] = Field(max_length=10)
    needs_human_review: bool

    @field_validator(
        "attack_type",
        "iocs",
        "mitre_techniques",
        "recommended_actions",
    )
    @classmethod
    def list_items_must_be_unique(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("List items must be unique.")
        return values


class ValidatedAnalysis(ModelAnalysis):
    unsupported_evidence: list[Evidence] = Field(default_factory=list)
    unsupported_iocs: list[str] = Field(default_factory=list)


class EvidenceLockSummary(StrictModel):
    schema_valid: bool
    supported_evidence_count: int = 0
    unsupported_evidence_count: int = 0
    supported_ioc_count: int = 0
    unsupported_ioc_count: int = 0
    issues: list[str] = Field(default_factory=list)


class InferenceMetadata(StrictModel):
    model_id: str
    model_family: str | None = None
    model_digest: str | None = None
    runtime: str
    endpoint: str
    latency_ms: float
    local_inference_calls: int
    external_inference_attempts: int
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_duration_ns: int | None = None
    mode: Literal["gemma", "development_stub"]


class AnalysisReport(StrictModel):
    run_id: str
    source_sha256: str
    status: Literal["completed", "failed_closed"]
    end_to_end_latency_ms: float
    tool_observations: ToolObservations
    analysis: ValidatedAnalysis
    evidence_lock: EvidenceLockSummary
    inference: InferenceMetadata
    error: str | None = None
    raw_model_output: str | None = Field(
        default=None,
        description="Present only on a parse failure, truncated for debugging.",
    )


def json_schema_for_gemma() -> dict[str, Any]:
    """Return the exact structured-output contract sent to Ollama."""

    return ModelAnalysis.model_json_schema()
