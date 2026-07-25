"""Schema validation and Evidence Lock."""

from __future__ import annotations

from pydantic import ValidationError

from .schema import (
    EvidenceLockSummary,
    ModelAnalysis,
    ToolObservations,
    ValidatedAnalysis,
)


class ModelOutputError(ValueError):
    pass


def parse_model_output(raw_output: str) -> ModelAnalysis:
    """Require the complete response to match the structured-output schema."""

    try:
        return ModelAnalysis.model_validate_json(raw_output.strip())
    except (ValidationError, ValueError) as exc:
        raise ModelOutputError(
            f"Model output did not match schema: {exc}"
        ) from exc


def apply_evidence_lock(
    candidate: ModelAnalysis,
    raw_email: str,
    observations: ToolObservations,
) -> tuple[ValidatedAnalysis, EvidenceLockSummary]:
    supported_evidence = []
    unsupported_evidence = []
    duplicate_evidence_count = 0
    seen_quotes: set[str] = set()
    for item in candidate.evidence:
        if item.quote in seen_quotes:
            duplicate_evidence_count += 1
            continue
        seen_quotes.add(item.quote)
        if item.quote in raw_email:
            supported_evidence.append(item)
        else:
            unsupported_evidence.append(item)

    observable_iocs = set(observations.urls)
    observable_iocs.update(observations.email_addresses)
    observable_iocs.update(observations.ip_addresses)
    supported_iocs = []
    unsupported_iocs = []
    for item in candidate.iocs:
        if item in raw_email and item in observable_iocs:
            supported_iocs.append(item)
        else:
            unsupported_iocs.append(item)

    issues: list[str] = []
    if duplicate_evidence_count:
        issues.append(
            f"{duplicate_evidence_count} duplicate evidence quote(s) "
            "were removed."
        )
    if unsupported_evidence:
        issues.append("One or more evidence quotes were not in the source.")
    if unsupported_iocs:
        issues.append("One or more IOCs were not deterministically observed.")
    if not supported_evidence:
        issues.append("The verdict had no source-grounded evidence.")
    if candidate.verdict == "suspicious" and not candidate.needs_human_review:
        issues.append("Suspicious verdicts require human review.")
    if candidate.verdict == "benign" and candidate.risk_score > 49:
        issues.append("Benign verdict conflicts with a high risk score.")
    if candidate.verdict == "malicious" and candidate.risk_score < 50:
        issues.append("Malicious verdict conflicts with a low risk score.")

    injection_observed = any(
        signal.kind == "prompt_injection"
        for signal in observations.signals
    )
    if injection_observed and candidate.verdict == "benign":
        issues.append(
            "Prompt-injection language was observed but the model returned "
            "benign; review is mandatory."
        )

    review_required = (
        candidate.needs_human_review
        or bool(issues)
        or candidate.verdict == "suspicious"
    )
    final = ValidatedAnalysis(
        **candidate.model_dump(
            exclude={"evidence", "iocs", "needs_human_review"}
        ),
        evidence=supported_evidence,
        iocs=list(dict.fromkeys(supported_iocs)),
        needs_human_review=review_required,
        unsupported_evidence=unsupported_evidence,
        unsupported_iocs=list(dict.fromkeys(unsupported_iocs)),
    )
    summary = EvidenceLockSummary(
        schema_valid=True,
        supported_evidence_count=len(supported_evidence),
        unsupported_evidence_count=len(unsupported_evidence),
        supported_ioc_count=len(final.iocs),
        unsupported_ioc_count=len(final.unsupported_iocs),
        issues=issues,
    )
    return final, summary
