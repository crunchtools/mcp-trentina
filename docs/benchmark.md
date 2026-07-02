# Provider benchmark (issue #43)

Runs the Layer 3 adversarial corpus through the Q-Agent (`quarantine_detect()`)
once per LLM provider and produces a head-to-head comparison: detection rate by
attack category, false-positive rate on benign content, risk-level calibration,
latency, and estimated token cost.

The question it answers: **does the choice of LLM behind the Q-Agent matter?**

## Why this corpus is hard

The corpus (`tests/adversarial_corpus.py`) is built to isolate what only Layer 3
can do. Every attack is written to slip past the cheaper layers:

- **Layer 1** (deterministic sanitization) strips hidden HTML, zero-width
  characters, base64 blobs, markdown-image exfil URLs, and literal delimiter
  tokens. The attacks carry none of those.
- **Layer 2** (Prompt Guard 2) is trained on instruction-override *syntax*
  ("ignore previous instructions", "you are now…"). The attacks use none of it.

What's left is pure semantics — social pretext, action-framed exfiltration,
second-order instructions, logic bombs, and attacks aimed at the detector
itself. That is exactly where a reasoning model earns its cost, and exactly
where providers should diverge. `tests/test_adversarial_corpus.py` proves (with
no API calls) that each attack genuinely reaches L3 intact.

## Running it

Credentials come from the same environment variables the server uses. Set the
ones you want to compare:

```bash
export GEMINI_API_KEY=...
export OPENAI_API_KEY=...
export ANTHROPIC_API_KEY=...
# Ollama is auto-detected by probing OLLAMA_BASE_URL (default localhost:11434)
```

```bash
# Every provider that has credentials configured:
uv run python benchmarks/provider_benchmark.py

# A specific subset:
uv run python benchmarks/provider_benchmark.py --providers gemini,anthropic

# See what would run without spending a single token:
uv run python benchmarks/provider_benchmark.py --dry-run

# Iterate quickly on one attack family:
uv run python benchmarks/provider_benchmark.py --categories detector_meta --limit 4
```

### Options

| Flag | Default | Purpose |
|------|---------|---------|
| `--providers` | all with creds | Comma-separated subset. |
| `--categories` | all | Comma-separated category filter. |
| `--limit N` | all | Run only the first N cases (smoke test). |
| `--concurrency N` | 4 | Max concurrent calls per provider. Lower it if you hit rate limits. |
| `--delay S` | 0 | Sleep S seconds after each call (gentler on rate limits). |
| `--retries N` | 0 | Retry transient failures (503/429/timeouts) up to N times with exponential backoff. Terminal errors (auth, schema) are not retried. Use when a cheap model's endpoint is capacity-throttling — e.g. `gemini-2.5-flash-lite` under load. |
| `--out DIR` | `benchmarks/results` | Where JSON + markdown land. |
| `--dry-run` | off | List providers and cases, call nothing. |

## Output

Each run writes two timestamped files to `--out`:

- `benchmark-<ts>.json` — full per-case results plus aggregates, for further
  analysis or regression tracking.
- `benchmark-<ts>.md` — the human-readable report (summary table, per-category
  detection, false-positive breakdown, and the attacks/benign that *every*
  provider got wrong). This is the artifact for the blog follow-up in issue #43.

## Cost figures

The `$/1k calls` column uses the editable `PRICING` table at the top of
`provider_benchmark.py` (USD per million input/output tokens). These are
estimates — update them to match your actual contract. Ollama is treated as
zero marginal cost.

## Metrics

- **Detection** — fraction of attacks flagged (`injection_detected == true`).
  Provider/detection errors are excluded from the denominator and reported
  separately in the `Errors` column.
- **FP rate** — fraction of benign content wrongly flagged. The benign set
  includes deliberate traps: security writing *about* injection, code that
  references `os.environ`/`subprocess`, and a legitimately quoted attack string.
- **Risk-cal** — of the attacks a provider caught, the fraction that met the
  expected minimum severity (`min_risk` in the corpus). Catches the case where a
  model notices something is off but under-rates a critical attack as "low".
- **Latency** — median and p95 wall-clock per call.

## Continuous detection gate (CI)

The periodic benchmark above is the deep, cross-provider comparison. For a
per-push early-warning signal, CI also runs `tests/test_l3_live.py` — the corpus
attacks through **live Gemini** (`gemini-2.5-flash`) — as the `Live L3
Detection (Gemini)` job.

It is engineered so a Google outage never reddens a PR:

- It only runs where a real key exists (`HAS_GEMINI_KEY`); fork PRs skip it.
- The test itself is gated on `GEMINI_API_KEY` + `TRENTINA_LIVE_L3=1`, so it
  never fires during normal local `pytest`.
- Transient failures are retried; if too few calls complete (a provider
  outage), it **skips as inconclusive** rather than failing.
- It fails only on a genuine detection regression — detection among *completed*
  calls dropping below the floor (`DETECTION_FLOOR`, currently 90%).

Run it locally the same way:

```bash
GEMINI_API_KEY=... TRENTINA_LIVE_L3=1 QUARANTINE_MODEL=gemini-2.5-flash \
  uv run pytest tests/test_l3_live.py -v
```
