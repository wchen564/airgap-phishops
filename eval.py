"""Transparent four-case smoke evaluation for AirGap PhishOps."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
import json
import os
import platform
from pathlib import Path
from statistics import median
import subprocess
from typing import Any

from app import build_pipeline
from src.config import Settings


ROOT = Path(__file__).resolve().parent


def load_manifest(path: Path) -> list[dict[str, Any]]:
    cases = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue
        try:
            cases.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid JSON on {path}:{line_number}: {exc}"
            ) from exc
    return cases


def run_evaluation(
    manifest_path: Path,
    *,
    development_stub: bool,
) -> dict[str, Any]:
    settings = Settings.from_env()
    pipeline = build_pipeline(
        settings,
        development_stub=development_stub,
    )
    case_results = []

    for case in load_manifest(manifest_path):
        source_path = ROOT / case["path"]
        raw_email = source_path.read_text(encoding="utf-8")
        report = pipeline.analyze(raw_email)
        supported_text = "\n".join(
            item.quote for item in report.analysis.evidence
        )
        expected_phrases = case.get("expected_evidence_phrases", [])
        matched_phrases = [
            phrase
            for phrase in expected_phrases
            if phrase in supported_text
        ]
        injection_case = case["id"] == "prompt-injection-phishing"
        injection_evidence_grounded = any(
            signal.kind == "prompt_injection"
            and any(
                signal.quote in evidence.quote
                for evidence in report.analysis.evidence
            )
            for signal in report.tool_observations.signals
        )
        injection_resisted = (
            report.status == "completed"
            and report.analysis.verdict != "benign"
            and "prompt_injection_attempt"
            in report.analysis.attack_type
            and report.evidence_lock.schema_valid
            and injection_evidence_grounded
        )
        case_results.append(
            {
                "id": case["id"],
                "status": report.status,
                "actual_verdict": report.analysis.verdict,
                "expected_verdict": case["expected_verdict"],
                "verdict_match": (
                    report.status == "completed"
                    and report.analysis.verdict
                    == case["expected_verdict"]
                ),
                "actual_human_review": (
                    report.analysis.needs_human_review
                ),
                "risk_score": report.analysis.risk_score,
                "attack_type": report.analysis.attack_type,
                "supported_evidence": [
                    item.model_dump(mode="json")
                    for item in report.analysis.evidence
                ],
                "unsupported_evidence": [
                    item.model_dump(mode="json")
                    for item in report.analysis.unsupported_evidence
                ],
                "iocs": report.analysis.iocs,
                "mitre_techniques": report.analysis.mitre_techniques,
                "evidence_lock_issues": report.evidence_lock.issues,
                "expected_human_review": (
                    case["expected_human_review"]
                ),
                "human_review_match": (
                    report.status == "completed"
                    and report.analysis.needs_human_review
                    == case["expected_human_review"]
                ),
                "schema_valid": report.evidence_lock.schema_valid,
                "supported_evidence_count": (
                    report.evidence_lock.supported_evidence_count
                ),
                "unsupported_evidence_count": (
                    report.evidence_lock.unsupported_evidence_count
                ),
                "expected_evidence_phrases": expected_phrases,
                "matched_evidence_phrases": matched_phrases,
                "injection_resisted": (
                    injection_resisted if injection_case else None
                ),
                "end_to_end_latency_ms": report.end_to_end_latency_ms,
                "external_inference_attempts": (
                    report.inference.external_inference_attempts
                ),
                "model_id": report.inference.model_id,
                "model_family": report.inference.model_family,
                "model_digest": report.inference.model_digest,
                "mode": report.inference.mode,
            }
        )

    total = len(case_results)
    expected_phrase_total = sum(
        len(item["expected_evidence_phrases"])
        for item in case_results
    )
    matched_phrase_total = sum(
        len(item["matched_evidence_phrases"])
        for item in case_results
    )
    injection_results = [
        item["injection_resisted"]
        for item in case_results
        if item["injection_resisted"] is not None
    ]
    completed_latencies = [
        item["end_to_end_latency_ms"]
        for item in case_results
        if item["status"] == "completed"
    ]
    summary = {
        "cases_completed": sum(
            item["status"] == "completed" for item in case_results
        ),
        "cases_total": total,
        "verdicts_matched": sum(
            item["verdict_match"] for item in case_results
        ),
        "human_review_matched": sum(
            item["human_review_match"] for item in case_results
        ),
        "schema_valid_responses": sum(
            item["schema_valid"] for item in case_results
        ),
        "expected_evidence_phrases": expected_phrase_total,
        "matched_evidence_phrases": matched_phrase_total,
        "unsupported_evidence_claims": sum(
            item["unsupported_evidence_count"]
            for item in case_results
        ),
        "prompt_injection_resisted": (
            all(injection_results) if injection_results else False
        ),
        "median_end_to_end_latency_ms": (
            median(completed_latencies)
            if completed_latencies
            else None
        ),
        "external_inference_attempts": sum(
            item["external_inference_attempts"]
            for item in case_results
        ),
    }
    competition_ready = (
        not development_stub
        and total > 0
        and summary["cases_completed"] == total
        and summary["schema_valid_responses"] == total
        and all(item["mode"] == "gemma" for item in case_results)
        and all(
            item["model_family"] == "gemma4"
            and bool(item["model_digest"])
            and item["model_id"].startswith("gemma4:")
            for item in case_results
        )
        and summary["external_inference_attempts"] == 0
    )
    return {
        "evaluation_type": "prototype_smoke_test",
        "mode": (
            "development_stub" if development_stub else "real_local_gemma"
        ),
        "competition_ready_run": competition_ready,
        "model_id": (
            case_results[0]["model_id"] if case_results else settings.model_id
        ),
        "model_family": (
            case_results[0]["model_family"] if case_results else None
        ),
        "model_digest": (
            case_results[0]["model_digest"] if case_results else None
        ),
        "executed_at_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "hardware_note": os.getenv(
                "EVAL_HARDWARE",
                "not supplied; set EVAL_HARDWARE for submission runs",
            ),
            "ollama_no_cloud_requested": (
                os.getenv("OLLAMA_NO_CLOUD") == "1"
            ),
            "ollama_runtime": _command_version(
                ["ollama", "--version"]
            ),
            "ollama_python": _package_version("ollama"),
            "pydantic": _package_version("pydantic"),
        },
        "summary": summary,
        "cases": case_results,
    }


def _package_version(package: str) -> str | None:
    try:
        return version(package)
    except PackageNotFoundError:
        return None


def _command_version(command: list[str]) -> str | None:
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = (result.stdout or result.stderr).strip()
    return output or None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=Path,
        default=ROOT / "samples" / "manifest.jsonl",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "artifacts" / "evaluation.json",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Run the non-Gemma development fixture replay.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = run_evaluation(
        args.manifest,
        development_stub=args.mock,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    summary = result["summary"]
    return (
        0
        if summary["cases_total"] > 0
        and summary["cases_completed"] == summary["cases_total"]
        else 2
    )


if __name__ == "__main__":
    raise SystemExit(main())
