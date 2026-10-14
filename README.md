# OpsPilot AI

OpsPilot AI is a local-first incident investigation dashboard for application logs. It helps an engineer move from raw logs to a defensible first hypothesis without sending incident data to a paid AI service or executing remediation commands.

## What the MVP does

- Provides a chat-first Streamlit workflow: paste logs or attach one or more `.log`, `.txt`, `.json`, `.jsonl`, or `.csv` files with the `+` control.
- Answers common incident follow-ups about the leading cause, supporting evidence, affected services, error lines, time window, and safe next checks using the current conversation's analysis.
- Parses timestamps, severity, service, and message text from plain text, JSON/JSONL, JSON arrays, CSV exports, and key-value (logfmt) logs.
- Infers likely severity from exception/error wording when a log has no explicit level, while preserving the original line as evidence.
- Detects transparent, explainable error patterns and simple statistical anomalies across dependencies, DNS/TLS, storage, CPU, queues, rate limits, process restarts, latency, and repeated errors.
- Correlates nearby events into an incident window.
- Ranks likely root causes using weighted evidence from patterns, ordering, and severity. A small local text classifier adds a secondary lead for high-signal error messages not already explained by a specific rule.
- Shows read-only recommended actions. It never runs shell commands, restarts services, or changes infrastructure.
- Exports a Markdown incident report.

## Architecture

The flow is: Browser -> Streamlit chat UI (`app.py`) -> local conversation responder (`opspilot/conversation.py`) -> analysis pipeline (`opspilot/pipeline.py`) -> parser, transparent detector, correlator, evidence ranker, optional classifier lead, safe actions, and reporter. Each stage is a small Python module so it can be tested independently and replaced later. The responder selects grounded answers from the analysis result; it does not call a hosted language model.

The local AI model is a supervised text classifier trained in this repository: word and character TF-IDF features feed a multinomial logistic-regression classifier for 12 common incident-cause categories. It is CPU-friendly, has no external model download, and is bundled as a small versioned artifact at `models/log_cause_classifier.joblib`. A separate 25% stratified holdout is used for the reported evaluation; after evaluation, the deployment artifact is refit on all labeled examples. The dataset is a small curated synthetic prototype set, so its scores are not calibrated probabilities and should not be presented as production accuracy. `models/evaluation.json` also records how many holdout cases passed the cautious model-score gate. Transparent rules take priority, and a model lead includes the triggering log lines. Unknown or ambiguous logs still get parsed and shown without forcing a specific cause.

The chat-style interaction uses a local deterministic responder—not ChatGPT or a general-purpose LLM. The model classifies log messages; it does not generate free-form text. Logs stay in the current app session and are not sent to an AI provider or saved as incident history.

## Directory structure

```text
opspilot-ai/
├── app.py                         # Streamlit dashboard entry point
├── Dockerfile                     # Reproducible container image
├── docker-compose.yml             # One-command local container run
├── requirements.txt               # Runtime dependencies
├── requirements-dev.txt           # Test/development dependencies
├── train_model.py                 # Reproducible classifier training and evaluation
├── .env.example                   # Optional UI configuration
├── .gitignore
├── README.md
├── sample_logs/
│   ├── checkout-service.log       # Database connection outage
│   ├── payments-tls.log           # Expired upstream certificate
│   ├── worker-queue.log           # Queue backlog in nested JSON logs
│   └── catalog-storage.log         # Full filesystem and failed writes
├── training_data/
│   └── log_cause_examples.jsonl    # Curated labeled examples for 12 cause types
├── models/
│   ├── log_cause_classifier.joblib # Bundled CPU-friendly model artifact
│   └── evaluation.json             # Dataset hash, versions, holdout metrics
├── opspilot/
│   ├── __init__.py
│   ├── actions.py                 # Safe recommended actions
│   ├── correlator.py              # Temporal/service correlation
│   ├── conversation.py             # Grounded chat answers and log detection
│   ├── detector.py                # Rules and transparent statistics
│   ├── ml_model.py                # Local classifier loading and cautious inference
│   ├── models.py                  # Typed dataclasses for pipeline output
│   ├── parser.py                  # Plain-text and JSON log parsing
│   ├── pipeline.py                # End-to-end orchestration
│   ├── ranker.py                  # Evidence-weighted root-cause ranking
│   └── reporter.py                # Markdown report generation
└── tests/
    ├── conftest.py
    ├── test_conversation.py
    ├── test_app.py
    ├── test_detector.py
    ├── test_parser.py
    ├── test_pipeline.py
    └── test_reporter.py
```

## Quick start on Windows PowerShell

From the `opspilot-ai` folder:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m streamlit run app.py
```

Open the URL printed by Streamlit, normally `http://localhost:8501`.

If PowerShell blocks activation, run this once in the same PowerShell window:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## Run with Docker Compose

```powershell
docker compose up --build
```

Then open `http://localhost:8501`. Stop it with `Ctrl+C`, or run `docker compose down` in another terminal.

## Using the dashboard

1. Choose one of four bundled incident scenarios, or paste/upload your own text-based logs.
2. OpsPilot parses the supplied records and responds with an incident summary, event counts, a ranked lead (when supported), matching evidence, and safe next checks.
3. Ask a follow-up such as “Why is this the leading cause?”, “Show the error lines”, “Which services are affected?”, or “What should I check next?”. Replies use the active analysis.
4. Expand **View findings and normalized events** to inspect parsed records, or download the Markdown incident report.

To retrain the model after editing its examples, activate the virtual environment and run:

```powershell
python train_model.py
```

This prints holdout accuracy and macro F1, writes the evaluation metadata, and then trains the artifact on the full dataset. Commit both files under `models/` with the dataset and code changes so local, Docker, and Streamlit deployments use the same model.

Supported examples include:

```text
2026-10-14 10:00:01 INFO checkout-api request started service=checkout-api request_id=abc
2026-10-14 10:00:03 ERROR checkout-api database connection refused host=postgres port=5432
```

and JSON lines such as:

```json
{"timestamp":"2026-10-14T10:00:03Z","level":"ERROR","service":"checkout-api","message":"database connection refused"}
```

The parser also accepts JSON arrays, common CSV columns (`timestamp`, `severity`, `service`, `message`), key-value logs such as `service=orders level=ERROR msg="payment failed"`, and less-structured lines such as `Exception: payment provider returned code XJ-73`. When no configured rule matches, OpsPilot still reports the error evidence and gives a cautious generic assessment instead of claiming a specific root cause. For clean logs it summarizes that no clear fault signal appeared in the supplied window.

## Design notes and next steps

The rules are deliberately visible in `opspilot/detector.py`; classifier training and the labeled examples are also versioned and reproducible. The UI marks model-derived hypotheses separately and shows their evidence. This makes the prototype useful for learning and interviewing: an engineer can explain whether a hypothesis came from an explicit rule or a learned text pattern instead of presenting either as proven causality.

Good follow-up iterations are adding Kubernetes event ingestion, structured log schema configuration, persistence for incident history, a feedback button for analyst-confirmed causes, and optional local LLM assistance behind an explicit feature flag.

## Verification

The test suite covers parsing, malformed input handling, pattern/anomaly detection, root-cause ranking, classifier-assisted analysis, chat behavior, app rendering, and report generation. Run it with:

```powershell
python -m pytest -q
```

