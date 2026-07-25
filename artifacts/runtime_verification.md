# Runtime verification

Observed on 2026-07-25 after the final code changes.

## Strict-offline server

Ollama was launched with:

```bash
OLLAMA_NO_CLOUD=1 ollama serve
```

The server log reported:

```text
Ollama cloud disabled: true
Listening on 127.0.0.1:11434 (version 0.32.3)
description="Apple M5" library=Metal
```

## Model identity

`python app.py --health` returned:

```text
model_id:       gemma4:e4b-it-qat
family:         gemma4
family valid:   true
digest:         ee665637121887cf3befff38abbb1be4ee117c7db867d97a67e29049ecd7e15f
size:           6,146,501,801 bytes
local calls:    1
external tries: 0
```

`ollama ps` after the real UI run returned:

```text
MODEL                PROCESSOR   CONTEXT
gemma4:e4b-it-qat    100% GPU    8192
```

## Executed checks

- 16/16 unit and security-regression tests passed.
- Four-case real-model evaluation completed with
  `competition_ready_run=true`.
- The real Gradio UI was opened on `127.0.0.1`, the prompt-injection fixture
  was analyzed by Gemma, and the rendered result showed `malicious`, risk 95,
  schema `PASS`, three supported quotes, zero rejected quotes, one local
  inference call, and zero external attempts.

The full measured evaluation is in `artifacts/evaluation.json`.
