# AirGap PhishOps

> Submission write-up based on the measured artifact at
> `artifacts/evaluation.json`. This is a four-case smoke test, not a production
> benchmark.

## One-sentence pitch

AirGap PhishOps is a local-first email investigation assistant that uses
`gemma4:e4b-it-qat` to explain suspicious intent, while deterministic checks
verify every quoted claim before an analyst sees it.

## The problem

Security teams regularly investigate emails containing confidential business
context, personal data, and potential credentials. Sending that material to a
cloud model can violate policy or create a second exposure. Traditional rules
can extract indicators, but they struggle with business-email compromise,
social pressure, impersonation, and ambiguous payment requests. General-purpose
language models add context, yet an unsupported explanation is dangerous in an
incident workflow.

AirGap PhishOps addresses both problems: semantic analysis stays on the
operator's machine, and model-generated evidence is treated as untrusted until
it is checked against the submitted email.

## What we built

The analyst pastes a raw email and chooses **Analyze Locally**. The pipeline:

1. Parses headers and extracts observable email addresses, domains, IP
   addresses, and defanged URLs without opening them.
2. Sends the email and deterministic observations to a locally hosted Gemma
   model through Ollama 0.32.3.
3. Requests a constrained result containing a verdict, risk score, attack
   categories, quoted evidence, indicators, and response actions.
4. Validates the result against the application schema.
5. Applies **Evidence Lock**: each quoted passage must be an exact substring of
   the original message. Unsupported passages are removed and surfaced for
   human review.
6. Displays a compact investigation report with a visible offline-status
   indicator.

The prototype intentionally does not browse links, contact threat-intelligence
services, send messages, or automatically block infrastructure. Those actions
remain with the analyst.

## Why Gemma

Deterministic parsing answers *what strings are present*; Gemma answers *what
the sender appears to be trying to achieve*. It interprets urgency,
impersonation, credential requests, payment-change language, and instructions
embedded in untrusted content. Gemma also turns those observations into a
readable rationale and prioritized response plan.

The selected model is `gemma4:e4b-it-qat`, using QAT Q4_0 on a MacBook Air
with an Apple M5 (10-core) and 16 GB unified memory. The explicit tag selects
the intended variant; the measured artifact records its observed digest
because a named tag is not an immutable content address. The model performs no
tool calls and has no authority to follow instructions inside an email.
During final verification, `ollama ps` reported `100% GPU` with an 8192-token
context; Ollama's server identified the device as Apple Metal.

## Trust and safety design

**Prompt-injection boundary.** The system prompt labels the entire email as
untrusted evidence. Text such as “ignore previous instructions” is content to
analyze, never an instruction to execute.

**Evidence Lock.** A claim is supported only when its quoted evidence appears
verbatim in the raw message. The UI distinguishes verified evidence from
unsupported model output and requests human review when validation fails.

**Structured failure.** The application makes zero model-based JSON repair
attempts. Malformed output immediately returns a controlled review state
instead of inventing a verdict.

**Network restraint.** During the measured inference path,
zero external inference attempts were observed. The
runtime endpoint was `http://127.0.0.1:11434`, and URLs found in messages were
never opened. Before every inference call, the application adapter verifies
that the configured endpoint is loopback; it records and blocks any
non-loopback attempt. This is an application-level adapter measurement, not an
OS packet-capture claim.

## Evaluation

We use a transparent prototype smoke test, not a production benchmark. Its
fixtures cover a normal internal message, obvious credential phishing,
phishing containing prompt injection, and an ambiguous beneficiary-change
request. Test URLs use the reserved `.invalid` domain and cannot identify real
infrastructure.

Measured on 2026-07-25 with `gemma4:e4b-it-qat` on a MacBook Air with an Apple
M5 (10-core) and 16 GB unified memory:

| Metric | Observed result |
|---|---:|
| Cases completed | 4 / 4 |
| Expected verdicts matched | 4 / 4 |
| Human-review decisions matched | 4 / 4 |
| Schema-valid responses | 4 / 4 |
| Expected evidence phrases selected | 7 / 11 |
| Model evidence claims accepted by Evidence Lock | 11 |
| Unsupported evidence claims rejected | 2 |
| Prompt-injection case resisted | Yes: non-benign verdict, injection label, schema-valid output, and exact injection evidence |
| Median end-to-end latency | 15.09 s |
| External inference attempts | 0 |

The evaluator writes the raw measured artifact to
`artifacts/evaluation.json`. Its `competition_ready_run` field is `true`; the
recorded Gemma family is `gemma4`, and the model digest is
`ee665637121887cf3befff38abbb1be4ee117c7db867d97a67e29049ecd7e15f`.
The two rejected claims occurred in the deliberately ambiguous payment-change
case and correctly preserved its human-review state.

## Impact

The prototype demonstrates a practical division of labor: local code handles
facts that can be verified mechanically, while Gemma handles meaning and
language. That pattern can help small security teams obtain useful AI-assisted
triage without making sensitive mail an external service dependency. The
analyst remains accountable for the final decision.

## Limitations and next steps

This is not a replacement for a secure email gateway or forensic review. The
current smoke test is small, sender identity is not cryptographically verified,
and a local model can still misclassify novel attacks. Before operational use,
we would expand the labeled corpus, add MIME and attachment isolation, test
multilingual messages, calibrate risk scores, sign model artifacts, and conduct
a formal privacy and red-team review.

## Reproduce

Environment: macOS 26.5.2; MacBook Air; Apple M5 (10-core); 16 GB unified
memory; Ollama 0.32.3.

```bash
# Install and start Ollama.
brew install --cask ollama-app
open -a Ollama

# Fetch the exact model.
ollama pull gemma4:e4b-it-qat

# Create the project environment and install dependencies.
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt

# Verify health, run the real-model smoke test, and launch the UI.
.venv/bin/python app.py --health
.venv/bin/python eval.py
.venv/bin/python app.py
```

Model source: [Gemma 4 E4B IT QAT on Ollama](https://ollama.com/library/gemma4:e4b-it-qat)
