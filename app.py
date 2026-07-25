"""AirGap PhishOps CLI and local Gradio interface."""

from __future__ import annotations

import argparse
import html
import json
import os
from pathlib import Path
import sys
from typing import Any

from src.config import Settings
from src.model import FixtureReplayClient, OllamaGemmaClient
from src.pipeline import AnalysisPipeline
from src.schema import AnalysisReport


ROOT = Path(__file__).resolve().parent
SAMPLE_DIR = ROOT / "samples"
SAMPLE_PATHS = {
    path.stem: path
    for path in sorted(SAMPLE_DIR.glob("*.txt"))
}


def build_pipeline(
    settings: Settings,
    *,
    development_stub: bool,
) -> AnalysisPipeline:
    client = (
        FixtureReplayClient()
        if development_stub
        else OllamaGemmaClient(settings)
    )
    return AnalysisPipeline(settings, client)


def format_report_html(report: AnalysisReport) -> str:
    """Render escaped HTML so model text can never become Markdown media."""

    analysis = report.analysis
    verdict_icon = {
        "benign": "✅",
        "suspicious": "⚠️",
        "malicious": "🚨",
    }[analysis.verdict]
    mode_text = (
        "REAL LOCAL GEMMA"
        if report.inference.mode == "gemma"
        else "DEVELOPMENT STUB — NOT GEMMA"
    )
    schema_text = "PASS" if report.evidence_lock.schema_valid else "FAIL-CLOSED"
    review_text = "YES" if analysis.needs_human_review else "NO"
    verdict_class = f"verdict-{analysis.verdict}"
    attack_tags = " ".join(
        f"<code>{_escape(label)}</code>"
        for label in analysis.attack_type
    ) or "<span>None assigned.</span>"

    evidence_items = "".join(
        "<li><q>"
        + _escape(item.quote)
        + "</q><span> — "
        + _escape(item.why)
        + "</span></li>"
        for item in analysis.evidence
    )
    if analysis.evidence:
        evidence_html = f"<ul>{evidence_items}</ul>"
    else:
        evidence_html = "<p>No model evidence passed Evidence Lock.</p>"

    if analysis.iocs:
        ioc_html = "<ul>" + "".join(
            f"<li><code>{_escape(ioc)}</code></li>"
            for ioc in analysis.iocs
        ) + "</ul>"
    else:
        ioc_html = "<p>None.</p>"

    action_html = (
        "<ol>"
        + "".join(
            f"<li>{_escape(action)}</li>"
            for action in analysis.recommended_actions
        )
        + "</ol>"
        if analysis.recommended_actions
        else "<p>No action proposed.</p>"
    )

    rejected_html = ""
    if analysis.unsupported_evidence or analysis.unsupported_iocs:
        rejected_items = "".join(
            "<li>Unsupported quote: <q>"
            + _escape(item.quote)
            + "</q></li>"
            for item in analysis.unsupported_evidence
        )
        rejected_items += "".join(
            f"<li>Unsupported IOC: <code>{_escape(ioc)}</code></li>"
            for ioc in analysis.unsupported_iocs
        )
        rejected_html = (
            "<section class=\"rejected\"><h3>Rejected model claims</h3>"
            f"<ul>{rejected_items}</ul></section>"
        )

    validation_html = ""
    if report.evidence_lock.issues:
        issue_items = "".join(
            f"<li>{_escape(issue)}</li>"
            for issue in report.evidence_lock.issues
        )
        validation_html = (
            "<section><h3>Validation notes</h3>"
            f"<ul>{issue_items}</ul></section>"
        )

    error_html = ""
    if report.error:
        error_html = (
            "<section class=\"rejected\"><h3>Controlled failure</h3>"
            f"<p>{_escape(report.error)}</p></section>"
        )

    return f"""\
<article class="phish-report">
  <h2 class="{verdict_class}">{verdict_icon} {analysis.verdict.upper()} ·
    risk {analysis.risk_score}/100</h2>
  <p class="runtime"><code>{mode_text}</code> ·
    <code>{_escape(report.inference.model_id)}</code></p>
  <table>
    <thead><tr><th>Control</th><th>Observed result</th></tr></thead>
    <tbody>
      <tr><td>Schema</td><td><strong>{schema_text}</strong></td></tr>
      <tr><td>Evidence Lock</td><td>
        <strong>{report.evidence_lock.supported_evidence_count}
        supported</strong>,
        {report.evidence_lock.unsupported_evidence_count} rejected</td></tr>
      <tr><td>Inference route</td><td>
        {report.inference.local_inference_calls} local /
        {report.inference.external_inference_attempts} external attempts</td>
      </tr>
      <tr><td>Human review</td><td><strong>{review_text}</strong></td></tr>
      <tr><td>End-to-end</td><td>
        {report.end_to_end_latency_ms / 1000:.2f} s</td></tr>
    </tbody>
  </table>
  <section><h3>Attack assessment</h3><p>{attack_tags}</p></section>
  <section><h3>Verified source evidence</h3>{evidence_html}</section>
  <section><h3>Observable IOCs</h3>{ioc_html}</section>
  <section><h3>Recommended analyst actions</h3>{action_html}</section>
  {rejected_html}
  {validation_html}
  {error_html}
</article>
"""


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def launch_ui(
    settings: Settings,
    *,
    development_stub: bool,
    inbrowser: bool,
    port: int,
) -> None:
    os.environ.setdefault("GRADIO_ANALYTICS_ENABLED", "False")
    import gradio as gr

    pipeline = build_pipeline(
        settings,
        development_stub=development_stub,
    )
    mode = (
        "⚠️ Development fixture replay — not Gemma"
        if development_stub
        else f"🔒 Local Gemma · {settings.model_id}"
    )

    def load_sample(name: str) -> str:
        path = SAMPLE_PATHS.get(name)
        return path.read_text(encoding="utf-8") if path else ""

    def analyze_for_ui(raw_email: str) -> tuple[str, dict[str, Any]]:
        report = pipeline.analyze(raw_email)
        return (
            format_report_html(report),
            report.model_dump(mode="json"),
        )

    css = """
    .gradio-container { max-width: 1180px !important; }
    .hero { text-align: center; margin-bottom: 0.5rem; }
    .privacy-note { opacity: 0.78; text-align: center; }
    .phish-report h2 { margin-top: 0; }
    .verdict-malicious { color: #b42318; }
    .verdict-suspicious { color: #b54708; }
    .verdict-benign { color: #067647; }
    .phish-report table { width: 100%; border-collapse: collapse; }
    .phish-report th, .phish-report td {
        border: 1px solid var(--border-color-primary);
        padding: 0.55rem 0.7rem;
        text-align: left;
    }
    .phish-report section { margin-top: 1rem; }
    .phish-report li { margin: 0.35rem 0; }
    .rejected {
        border-left: 4px solid #d92d20;
        padding-left: 0.8rem;
    }
    """
    with gr.Blocks(
        analytics_enabled=False,
        title="AirGap PhishOps",
    ) as demo:
        gr.Markdown(
            "# AirGap PhishOps\n"
            "### Local intelligence. Verifiable evidence. Human authority.",
            elem_classes=["hero"],
        )
        gr.Markdown(
            f"**{mode}** · URLs are parsed but never opened · "
            "Unsupported quotes are rejected",
            elem_classes=["privacy-note"],
        )
        with gr.Row():
            with gr.Column(scale=5):
                sample = gr.Dropdown(
                    choices=list(SAMPLE_PATHS),
                    value="injection_phishing",
                    label="Safe demo fixture",
                )
                load_button = gr.Button("Load fixture")
                email_box = gr.Textbox(
                    label="Raw email",
                    lines=22,
                    placeholder="Paste a complete raw email here…",
                )
                analyze_button = gr.Button(
                    "Analyze locally",
                    variant="primary",
                )
            with gr.Column(scale=6):
                report_box = gr.HTML(
                    "<p>Load a fixture or paste an email to begin.</p>"
                )
        with gr.Accordion("Audit JSON", open=False):
            json_box = gr.JSON(label="Validated analysis report")

        load_button.click(
            fn=load_sample,
            inputs=sample,
            outputs=email_box,
        )
        sample.change(
            fn=load_sample,
            inputs=sample,
            outputs=email_box,
        )
        analyze_button.click(
            fn=analyze_for_ui,
            inputs=email_box,
            outputs=[report_box, json_box],
        )
        demo.load(
            fn=lambda: load_sample("injection_phishing"),
            outputs=email_box,
        )

    demo.launch(
        server_name="127.0.0.1",
        server_port=port,
        inbrowser=inbrowser,
        share=False,
        show_error=True,
        footer_links=[],
        enable_monitoring=False,
        theme=gr.themes.Soft(),
        css=css,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Local, evidence-locked email triage with Gemma 4."
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--file", type=Path, help="Analyze a raw email file.")
    source.add_argument("--text", help="Analyze raw email text.")
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Use the clearly labeled fixture replay for pipeline development.",
    )
    parser.add_argument(
        "--health",
        action="store_true",
        help="Check the local Ollama endpoint and required model.",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not open the UI automatically.",
    )
    parser.add_argument("--port", type=int, default=7860)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    settings = Settings.from_env()

    if args.health:
        if args.mock:
            print("--health checks real Ollama; remove --mock.", file=sys.stderr)
            return 2
        try:
            result = OllamaGemmaClient(settings).healthcheck()
        except Exception as exc:
            result = {
                "reachable": False,
                "required_model": settings.model_id,
                "endpoint": settings.ollama_host,
                "error": f"{type(exc).__name__}: {exc}",
            }
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return (
            0
            if result.get("model_present")
            and result.get("model_family_valid")
            else 2
        )

    raw_email: str | None = None
    if args.file:
        raw_email = args.file.read_text(encoding="utf-8")
    elif args.text:
        raw_email = args.text

    if raw_email is not None:
        report = build_pipeline(
            settings,
            development_stub=args.mock,
        ).analyze(raw_email)
        print(report.model_dump_json(indent=2))
        return 0 if report.status == "completed" else 2

    launch_ui(
        settings,
        development_stub=args.mock,
        inbrowser=not args.no_browser,
        port=args.port,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
