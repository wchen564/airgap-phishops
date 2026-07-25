# AirGap PhishOps design record

## Decision

Use a hybrid local pipeline:

1. Deterministic code extracts only observable facts.
2. Gemma 4 assesses intent and proposes a structured analysis.
3. The application validates the schema.
4. Evidence Lock separates supported and unsupported claims.
5. The UI presents only the validated analysis and preserves rejected claims
   for audit.

The pre-implementation logic prototype confirmed that candidate and validated
analysis must remain separate states, unsupported evidence must be visible, and
unsupported evidence must force human review. Those decisions are now encoded
in `src/pipeline.py` and `src/validator.py`.

## Why Gemma is necessary

A URL parser can identify a defanged URL and a header parser can compare
`From` with `Reply-To`, but neither can reliably infer whether language
represents impersonation, credential theft, business-email compromise, a
legitimate verification control, or an instruction aimed at the analyzing
model. Gemma owns that semantic judgment. Deterministic code does not assign
the primary verdict or risk score.

## State model

| State | Trusted material | Untrusted material |
|---|---|---|
| Observed | Header values, extracted strings, syntax flags | Sender intent |
| Candidate | Schema shape only | Gemma verdict, quotes, IOCs, actions |
| Validated | Exact-source quotes and observed IOCs | Rejected model claims |
| Presented | Validation metadata and review decision | None promoted silently |

## Threat model

### In scope

- Instructions embedded in email text that try to control the analyzer.
- Hallucinated or paraphrased model evidence.
- Model-produced IOCs not present in the message.
- Malformed or extra-field model JSON.
- Accidental configuration of a remote inference endpoint.
- Resource pressure from unexpectedly long input.
- Ambiguous classification that should reach a person.

### Controls

- A system message defines email and observations as untrusted data.
- The model receives no callable tools.
- The application never requests extracted URLs.
- Pydantic rejects schema drift and extra fields.
- Exact, case-sensitive substring checks ground evidence.
- An IOC must be both in the raw source and deterministically extracted.
- The inference adapter authorizes loopback hosts only.
- Oversized input is rejected without silent truncation.
- Schema/parser/inference failures produce `failed_closed`; rejected evidence
  remains a completed, visibly qualified result and forces human review.

### Out of scope

- Operating-system packet capture or firewall enforcement.
- Full MIME/attachment detonation.
- SPF, DKIM, or DMARC cryptographic verification.
- Live threat-intelligence reputation.
- Automatic quarantine, account action, or infrastructure blocking.
- Production calibration or claims based on the four-case smoke test.

## Model decision

Default: `gemma4:e4b-it-qat`.

- Explicit tag selects the intended E4B IT QAT variant; the evaluator records
  the observed digest because a named tag is not an immutable content address.
- QAT reduces the local memory footprint.
- E4B is a practical starting point for a 16 GB Apple-silicon laptop.
- `think=false` keeps structured output and latency more predictable.
- `temperature=0` reduces run-to-run variance.
- `num_ctx=8192` is intentionally modest; the 12,000-character input cap
  leaves room for the system prompt, JSON Schema, observations, and output.

Fallback: `gemma4:e2b-it-qat`, configured through `GEMMA_MODEL`, if target
hardware cannot sustain E4B.

## Honest measurement

`eval.py` labels runs from the fixture replay as non-competition-ready. Only a
run with `mode=real_local_gemma` may populate submission metrics. The reported
external-call number is the inference adapter's observed/blocked request count,
not a system-wide network trace.
