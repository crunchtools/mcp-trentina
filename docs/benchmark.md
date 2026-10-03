# Provider benchmark (issue #43)

Runs the Layer 3 adversarial corpus through the Q-Agent (`quarantine_detect()`)
once per LLM provider and produces a head-to-head comparison: detection rate by
attack category, false-positive rate on benign content, risk-level calibration,
latency, and estimated token cost.

The question it answers: **does the choice of LLM behind the Q-Agent matter?**

## Why this corpus is hard

The corpus (`tests/adversarial_corpus.py`) is built to isolate what only Layer 3
can do. Every attack is written to slip past the cheaper layers:

- **Layer 1** (deterministic detection) counts hidden markup, zero-width
  characters, base64 blobs, markdown-image exfil URLs, and literal delimiter
  tokens. The attacks carry none of those.
- **Layer 2** was Prompt Guard 2, trained on instruction-override *syntax*
  ("ignore previous instructions", "you are now…"). Most attacks use none of
  it; the structural ones do, and 8 of 39 score above 0.9 (see the sweep below).
  The default L2 model since 0.55.0 catches most of them anyway (see
  [L2 model comparison](#l2-model-comparison-350)); the corpus still measures
  L3 because L3 reads every call whatever L2 concluded.

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
export OPENROUTER_API_KEY=...   # one model per run: QUARANTINE_MODEL=vendor/model
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
| `--corpus` | `internal` | `internal`, `external`, or `both` (reported separately). See below. |
| `--external-split` | `test` | External split: `test` (262), `train` (1,044), `all` (1,306). |
| `--categories` | all | Comma-separated category filter. |
| `--limit N` | all | Run only the first N cases of each corpus (smoke test). |
| `--concurrency N` | 4 | Max concurrent calls per provider. Lower it if you hit rate limits. |
| `--delay S` | 0 | Sleep S seconds after each call (gentler on rate limits). |
| `--retries N` | 0 | Retry transient failures (503/429/timeouts) up to N times with exponential backoff. Terminal errors (auth, schema) are not retried. Use when a cheap model's endpoint is capacity-throttling — e.g. `gemini-2.5-flash-lite` under load. |
| `--out DIR` | `benchmarks/results` | Where JSON + markdown land. |
| `--l2-only` | off | Score through L1+L2 and sweep `l2_threshold`; no provider calls. |
| `--dry-run` | off | List providers, cases and a projected cost; call nothing. |

## Output

Each run writes two timestamped files to `--out`:

- `benchmark-<ts>.json` — full per-case results plus aggregates, for further
  analysis or regression tracking.
- `benchmark-<ts>.md` — the human-readable report (summary table, per-category
  detection, false-positive breakdown, and the attacks/benign that *every*
  provider got wrong). This is the artifact for the blog follow-up in issue #43.

## External corpus (issue #85)

`--corpus external` runs [`jackhhao/jailbreak-classification`](https://huggingface.co/datasets/jackhhao/jailbreak-classification)
(Apache-2.0), a third-party labeled set, so the defense is not graded only
against attacks its own author wrote, and the FP rate gets a denominator in
the hundreds. `benchmarks/external_corpus.py` pins one dataset revision and
checks each split's SHA-256, downloads on first use into `benchmarks/data/`
(gitignored, never vendored), and maps rows onto `Case` as
`external_jailbreak` / `external_benign`.

Read its results for what they are. It is **direct jailbreak** (user to
model, DAN-style personas), not indirect injection in retrieved content,
which is Trentina's threat model. It measures L2, which is trained on exactly
this syntax, and over-triggering on benign roleplay ("Act as a yoga
instructor…"), which looks like our `role_reassignment` attacks. L3 still
runs on it in a provider pass, and should catch nearly all of these loud
attacks, but that proves only that it handles the easy case: the semantic
gap is measured on the internal corpus alone.

The two are never blended: `--corpus both` writes a separate report, sweep
and JSON block (`providers[].corpora.<name>`, `l2.<name>`) per corpus. The
dataset has no severity labels, so Risk-cal is n/a for it rather than a
number invented to fill the column. A full external pass is 262 L3 calls per
provider; `--dry-run` prints a projected cost first.

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

## L2 threshold sweep (issue #86)

The L2 model's threshold is a cutoff applied to its continuous score after
inference, so one scoring pass answers it for every threshold. Every run passes each case once through `defense._stage_one`, the
recipe `defend()` uses: L2 scores the original and, when L1 normalized
anything, L1's copy too, keeping the stronger score, which is the one
production thresholds.

The score is stored as `l2_malicious_score` per case and under `l2.scores` in
the JSON. The report gains a sweep table: detection, FP rate and precision at
0.05 to 0.95 with the threshold in force in bold, and the cutoff with the best
separation (max detection minus FP rate, over the observed scores plus one
just above the highest, which flags nothing; shown from 30 benign cases up).

```bash
# L2 only: no provider, no tokens. Scores whichever model CLASSIFIER_MODEL /
# CLASSIFIER_MODEL_PATH selects; the report names it.
CLASSIFIER_MODEL_PATH=/path/to/export uv run python benchmarks/provider_benchmark.py --l2-only
```

Recompute a different cut from the stored scores with
`benchmarks/l2_sweep.py`; no rerun needed.

### Result: Prompt Guard 2 stays at 0.5 (2026-09-28)

Internal corpus (39 attacks, 9 benign): the scores are bimodal. Nothing
lands between 0.10 and 0.90, so every threshold in that band flags the same
8 attacks and the same benign case (`trap-quoted-attack-string`, 0.94). The
attacks are written for L3, so that is the corpus working, and 9 benign
cases cannot choose a threshold.

External corpus, all 1,306 rows (666 jailbreak, 640 benign),
`--l2-only --corpus external --external-split all`:

| Threshold | Detection | False positives |
|-----------|-----------|-----------------|
| 0.0254 (best separation) | 642/666 (96.4%) | 9/640 (1.4%) |
| 0.20 | 633/666 (95.0%) | 3/640 (0.5%) |
| **0.50** (default) | 624/666 (93.7%) | 1/640 (0.2%) |
| 0.90 | 610/666 (91.6%) | 0/640 |

The curve is flat from 0.20 to 0.60: no cliff sits near the default. The
one false positive at 0.5 is roleplay asking a villain to "reveal your
nefarious plans" (0.86); the ones added below 0.5 are more roleplay
personas and a task prompt.

0.5 stays, for three reasons. Production traffic is almost all benign tool
output, not a balanced set, so a false positive costs far more there than
here: a warning under `flag`, a refused call under `block`. L3 judges every
call whatever L2 says, so an attack L2 misses is still read. And the
cheaper cutoffs buy little: 0.20 gains 1.3 points of detection for three
times the false positives, the best-separation point 2.7 points for nine
times.

A profile cannot loosen this. `defend()` flags on the model's own MALICIOUS
label (its manifest threshold, or `CLASSIFIER_THRESHOLD`) or on a profile's
`l2_threshold` when one is set, so the profile setting can only make L2 more
sensitive.

Not measured: false positives on retrieved content (web pages, code,
mail), which is what L2 actually reads in production. The benign half here
is prompts.

## L2 model comparison (#350)

L2's model is a setting since 0.55.0. Two ship in the image:
`prompt-injection-guard-small` (Horizon-Labs, mmBERT-small, Apache-2.0, the
default at 0.7) and `prompt-guard-2-86m` (Meta, mDeBERTa-base, Llama 4
Community License, 0.5). Measured 2026-10-03, L2 alone, 512-token windows at
stride 446, each model at its own threshold:

| Set | Prompt Guard 2 86M | prompt-injection-guard-small |
|---|---|---|
| Internal corpus, attacks caught | 14/39 | 37/39 |
| Internal corpus, benign flagged | 2/9 | 1/9 |
| Internal attacks planted in 12K-char benign documents | 5/39 | 26/39 |
| deepset/prompt-injections test split | 10/60, 0 FP | 29/60, 0 FP |
| xTRam1/safe-guard test | 338/650, 2/1410 FP | 466/650, 17/1410 FP |
| jackhhao jailbreak, all rows | 641/666, 1/640 FP | 559/666, 2/640 FP |
| Benign retrieved documents (stdlib source, changelogs) flagged | 2/150 | 2/150 |
| Throughput, paired runs on one CPU | 1x | 2.9x |

The new model is never worse on the internal corpus case by case: it misses
two attacks, and Prompt Guard 2 misses both of them too. It catches the
whole of `exfil_action`, `tool_invocation` and `conditional_trigger`, which
Prompt Guard 2 scored at 0.00. Prompt Guard 2 is the better detector of
DAN-style jailbreaks, which are user-to-model attacks rather than the tool
output L2 reads. The new model's training data includes the deepset train
and jackhhao splits, so those rows flatter it; the planted-document set and the internal
corpus are ours.

0.7 rather than 0.5: at 0.5 it flags 6 of the 150 benign documents (4.0%)
and at 0.7 two, the same as Prompt Guard 2, for one fewer planted-document
catch. The near misses on benign text are code and changelogs scoring 0.5
to 0.67.

**Trying another model.** Export it in the model-builder image with
`scripts/export_l2_model.py` (pinned revision, manifest naming the malicious
outputs and threshold), mount the directory and set `CLASSIFIER_MODEL_PATH`.
Score it with `--l2-only` above, then run `tests/test_l2_integration.py`
against it with `TRENTINA_REQUIRE_L2_MODEL=1`; a model with no recorded
expectations runs only the benign checks until its row is added.

## Continuous detection gate (CI)

The periodic benchmark above is the deep, cross-provider comparison. For a
per-push early-warning signal, CI also runs `tests/test_l3_live.py` — the corpus
attacks through a **live model on OpenRouter** (`google/gemini-2.5-flash`),
production's L3 provider — as the `Live L3 Detection (OpenRouter)` job.

It is engineered so a provider outage never reddens a PR:

- It only runs where `OPENROUTER_API_KEY` is available; without it (fork PRs)
  the job says so with a warning rather than passing silently.
- The test itself is gated on the provider's key + `TRENTINA_LIVE_L3=1`, so it
  never fires during normal local `pytest`. `TRENTINA_LIVE_L3_PROVIDER`
  (default `openrouter`) picks another provider, e.g. `gemini`.
- Transient failures are retried; if too few calls complete (a provider
  outage), it **skips as inconclusive** rather than failing.
- It fails only on a genuine detection regression — detection among *completed*
  calls dropping below the floor (`DETECTION_FLOOR`, currently 90%).

Run it locally the same way:

```bash
OPENROUTER_API_KEY=... TRENTINA_LIVE_L3=1 QUARANTINE_MODEL=google/gemini-2.5-flash \
  uv run pytest tests/test_l3_live.py -v
```

## OpenRouter comparison (2026-09-25)

Cheap models with strict structured output, full corpus (39 attacks, 9
benign), through OpenRouter with `data_collection: deny`. Latency is what
decides: L3 runs on every tool response, and a user-facing call waits at most
`TRENTINA_L3_THROTTLE_BUDGET` (20s).

| Model | Detection | FP | p50 | p95 | $/1k calls |
|-------|-----------|----|-----|-----|------------|
| `google/gemini-2.5-flash-lite` | 37/39 | 1–2/9 | 1.0s | 1.5s | $0.09 |
| `deepseek/deepseek-v4-flash` (reasoning off) | 36/39 | 0/9 | 6.0s | 11.6s | $0.05 |
| `deepseek/deepseek-v4-flash` | 37/38 | 1/9 | 11.7s | 31.3s | $0.08 |
| `z-ai/glm-5.3-flash` | 37/37 | 1/9 | 12.2s | 39.7s | $0.23 |
| `qwen/qwen3-235b-a22b-2507` | 34/39 | 0–1/9 | 6.0s | 11.6s | $0.09 |
| `xiaomi/mimo-v2.6-flash` (reasoning off) | 37/38 | 1/9 | 17.4s | 73.5s | $0.09 |
| `openai/gpt-oss-120b` | 38/39 | 2/9 | 9.5s | 20.2s | $0.06 |
| `openai/gpt-oss-safeguard-20b` | 35/39 | 1/9 | 1.0s | 2.0s | $0.18 |

`qwen/qwen3.5-flash` has no host that passes `data_collection: deny` (404 on
every call). Detection differences are one or two cases on a 48-case corpus;
latency differences are an order of magnitude.

### Newer Gemini Flash models (2026-09-25)

Two runs of the corpus each (78 attacks, 18 benign), same routing.

| Model | Detection | FP | p50 | p95 | $/1k calls |
|-------|-----------|----|-----|-----|------------|
| `google/gemini-2.5-flash-lite` | 74/78 | 3/18 | 1.0s | 1.9s | $0.09 |
| `google/gemini-3.1-flash-lite` | 76/78 | 2/18 | 1.6s | 2.6s | $0.37 |
| `google/gemini-2.5-flash` | 78/78 | 3/18 | 1.8s | 3.3s | $0.56 |
| `google/gemini-3.5-flash-lite` | 76/78 | 0/18 | 1.7s | 12.2s | $0.48 |
| `google/gemini-3.8-flash` | 68/68 (10 timed out) | 2/18 | 44.8s | 69.8s | $2.16 |

2.5 Flash-Lite stays the default: nothing newer separates from it by more
than the corpus can resolve, at a quarter of the cost. Gemini 3.5 and later
return 404 through OpenRouter when the request carries `temperature` under
`require_parameters`; the rows above were measured without it, so moving to
one needs the driver to drop `temperature` for those models first.
