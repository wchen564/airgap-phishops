"""End-to-end local analysis pipeline."""

from __future__ import annotations

from hashlib import sha256
from time import perf_counter
from typing import Any
from uuid import uuid4

from .config import Settings
from .model import FixtureReplayClient, ModelClient, ModelResponse
from .prompts import build_prompts
from .schema import (
    AnalysisReport,
    EvidenceLockSummary,
    InferenceMetadata,
    ToolObservations,
    ValidatedAnalysis,
    json_schema_for_gemma,
)
from .tools import extract_observations
from .validator import (
    ModelOutputError,
    apply_evidence_lock,
    parse_model_output,
)


class AnalysisPipeline:
    def __init__(self, settings: Settings, model_client: ModelClient):
        self.settings = settings
        self.model_client = model_client

    def analyze(self, raw_email: str) -> AnalysisReport:
        started = perf_counter()
        source_hash = sha256(raw_email.encode("utf-8")).hexdigest()
        input_issue = self._validate_input(raw_email)
        if input_issue:
            observations = _empty_observations(
                "Input was rejected before deterministic parsing."
            )
            return self._failed_report(
                source_hash=source_hash,
                observations=observations,
                started=started,
                error=input_issue,
                issue=input_issue,
            )

        try:
            observations = extract_observations(raw_email)
        except Exception as exc:
            observations = _empty_observations(
                f"Parser failed safely: {type(exc).__name__}"
            )
            return self._failed_report(
                source_hash=source_hash,
                observations=observations,
                started=started,
                error=f"{type(exc).__name__}: {exc}",
                issue="Deterministic email parsing did not complete.",
            )

        schema = json_schema_for_gemma()
        system_prompt, user_prompt = build_prompts(
            raw_email,
            observations,
            schema,
        )

        response: ModelResponse | None = None
        try:
            response = self.model_client.generate(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                schema=schema,
            )
            candidate = parse_model_output(response.content)
            validated, lock_summary = apply_evidence_lock(
                candidate,
                raw_email,
                observations,
            )
        except ModelOutputError as exc:
            return self._failed_report(
                source_hash=source_hash,
                observations=observations,
                started=started,
                error=str(exc),
                issue="Gemma output failed schema validation.",
                response=response,
                raw_output=response.content if response else None,
            )
        except Exception as exc:
            return self._failed_report(
                source_hash=source_hash,
                observations=observations,
                started=started,
                error=f"{type(exc).__name__}: {exc}",
                issue="Local inference did not complete.",
                response=response,
            )

        return AnalysisReport(
            run_id=str(uuid4()),
            source_sha256=source_hash,
            status="completed",
            end_to_end_latency_ms=_elapsed_ms(started),
            tool_observations=observations,
            analysis=validated,
            evidence_lock=lock_summary,
            inference=_metadata_from_response(response),
        )

    def _validate_input(self, raw_email: str) -> str | None:
        if not raw_email.strip():
            return "Raw email is empty."
        if len(raw_email) > self.settings.max_email_chars:
            return (
                f"Email has {len(raw_email):,} characters; the configured "
                f"safe limit is {self.settings.max_email_chars:,}. It was "
                "not truncated or sent to the model."
            )
        return None

    def _failed_report(
        self,
        *,
        source_hash: str,
        observations: ToolObservations,
        started: float,
        error: str,
        issue: str,
        response: ModelResponse | None = None,
        raw_output: str | None = None,
    ) -> AnalysisReport:
        observed_iocs = list(
            dict.fromkeys(
                observations.urls
                + observations.email_addresses
                + observations.ip_addresses
            )
        )
        analysis = ValidatedAnalysis(
            verdict="suspicious",
            risk_score=50,
            attack_type=["analysis_failure"],
            evidence=[],
            iocs=observed_iocs,
            mitre_techniques=[],
            recommended_actions=[
                "Do not act on this automated result.",
                "Escalate the original message for manual review.",
            ],
            needs_human_review=True,
            unsupported_evidence=[],
            unsupported_iocs=[],
        )
        lock = EvidenceLockSummary(
            schema_valid=False,
            supported_evidence_count=0,
            unsupported_evidence_count=0,
            supported_ioc_count=len(observed_iocs),
            unsupported_ioc_count=0,
            issues=[issue],
        )
        return AnalysisReport(
            run_id=str(uuid4()),
            source_sha256=source_hash,
            status="failed_closed",
            end_to_end_latency_ms=_elapsed_ms(started),
            tool_observations=observations,
            analysis=analysis,
            evidence_lock=lock,
            inference=(
                _metadata_from_response(response)
                if response
                else _failure_metadata(self.settings, self.model_client)
            ),
            error=error,
            raw_model_output=(
                raw_output[:2_000] if raw_output is not None else None
            ),
        )


def _metadata_from_response(response: ModelResponse) -> InferenceMetadata:
    return InferenceMetadata(
        model_id=response.model_id,
        model_family=response.model_family,
        model_digest=response.model_digest,
        runtime=response.runtime,
        endpoint=response.endpoint,
        latency_ms=response.latency_ms,
        local_inference_calls=response.local_inference_calls,
        external_inference_attempts=response.external_inference_attempts,
        prompt_tokens=response.prompt_tokens,
        completion_tokens=response.completion_tokens,
        total_duration_ns=response.total_duration_ns,
        mode=response.mode,
    )


def _failure_metadata(
    settings: Settings,
    model_client: ModelClient,
) -> InferenceMetadata:
    stub = isinstance(model_client, FixtureReplayClient)
    audit = getattr(model_client, "last_audit", None)
    identity = getattr(model_client, "model_identity", None)
    return InferenceMetadata(
        model_id=(
            FixtureReplayClient.model_id if stub else settings.model_id
        ),
        model_family=getattr(identity, "family", None),
        model_digest=getattr(identity, "digest", None),
        runtime="in_process_fixture_replay" if stub else "ollama",
        endpoint="none" if stub else settings.ollama_host,
        latency_ms=0.0,
        local_inference_calls=getattr(audit, "local_calls", 0),
        external_inference_attempts=getattr(
            audit,
            "external_attempts",
            0,
        ),
        mode="development_stub" if stub else "gemma",
    )


def _elapsed_ms(started: float) -> float:
    return (perf_counter() - started) * 1_000


def _empty_observations(note: str) -> ToolObservations:
    return ToolObservations(
        headers={},
        email_addresses=[],
        urls=[],
        ip_addresses=[],
        url_features=[],
        signals=[],
        header_anomalies=[note],
        truncated_fields=[],
    )
