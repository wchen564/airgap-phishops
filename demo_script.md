# AirGap PhishOps — 112-second demo script

> Replace bracketed fields only with observed results. Rehearse once on the
> presentation machine; inference time is included in the timeline.

## 0:00–0:10 — Problem

**On screen:** Title, then the empty app.

**Say:** “A suspicious email may contain the very information an organization
cannot upload to a cloud AI. AirGap PhishOps investigates it locally and makes
the model prove its claims.”

## 0:10–0:27 — Establish the local path

**On screen:** Point to the model and privacy badges.

**Say:** “This build runs gemma4:e4b-it-qat, QAT Q4_0, through Ollama 0.32.3 on
an M5 10-core MacBook Air with 16 gigabytes of memory. Before each request, the
adapter verifies the 127.0.0.1:11434 endpoint and records or blocks anything
else. Ollama reports 100 percent GPU execution with an 8192-token context.
The measured run recorded zero external inference attempts.”

## 0:27–0:39 — Load the adversarial fixture

**On screen:** Select `injection_phishing.txt`. Highlight the fake system
instruction and defanged `.invalid` URL.

**Say:** “This message is both credential phishing and a prompt-injection
attempt. It tells the analyzer to ignore its instructions, call the email
benign, and hide the URL.”

## 0:39–0:59 — Run real inference

**On screen:** Click **Analyze Locally**. While the button shows that local
analysis is running, explain the parsing, Gemma, schema, and Evidence Lock
stages.

**Say:** “The parser first collects headers and indicators. Gemma then reasons
about intent, but it receives the email inside an explicit untrusted-content
boundary. Its structured response has no permission to browse, execute, or
change the machine.”

## 0:59–1:17 — Show the result

**On screen:** Show the actual verdict, risk score, attack category, and
defanged IOC.

**Say:** “The observed result is malicious with a risk score of
95. It identifies credential phishing and a prompt-injection attempt, and retains the
defanged indicator. Most importantly, the embedded instruction did not control
the result: Gemma returned malicious, labeled the injection attempt, and
grounded that finding in an exact quote from the fake system message.”

## 1:17–1:33 — Demonstrate Evidence Lock

**On screen:** Highlight two verified quotes in both the report and original
email. Briefly show the unsupported-evidence field.

**Say:** “Evidence Lock checks every model quote against the raw message. These
passages are exact matches. Any unsupported quote is removed, counted, and can
force human review instead of silently becoming evidence.”

## 1:33–1:45 — Show honest evaluation

**On screen:** Open the evaluation summary.

**Say:** “Our prototype smoke test completed 4 of 4 cases,
matched all 4 expected verdicts, and produced 4 of 4
schema-valid responses. Median end-to-end latency was 15.09
seconds. These are recorded run results, not benchmark claims.”

## 1:45–1:52 — Close

**On screen:** Return to the report and show recommended analyst actions.

**Say:** “Gemma supplies contextual reasoning; deterministic code supplies
verification; the analyst keeps authority. That is private, evidence-locked
phishing triage.”
