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
recipe `defend()` uses: L2 reads the arrived bytes once (#359), and that
score is the one production thresholds.

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

## L2 model comparison (#350, #353)

L2's model is a setting since 0.55.0. Two ship in the image:
`prompt-injection-guard-small` (Horizon-Labs, mmBERT-small, Apache-2.0, the
default at 0.7) and `prompt-guard-2-86m` (Meta, mDeBERTa-base, Llama 4
Community License, 0.5). Two more were measured and rejected in #353:
`deberta-v3-base-prompt-injection-v2` (ProtectAI, mirrored as
`RedHatAI/...` and shipped in OpenShift AI, Apache-2.0) and `PIGuard`
(ACL 2025, MIT), both DeBERTa-v3-base and English-only.

Measured 2026-10-03, each model our own ONNX export from pinned safetensors,
scored through `classify()` (512-token windows at stride 446), each at its
own threshold. The planted set puts each attack at a random line of a
~12K-character benign document (`/usr/share/doc` READMEs and changelogs,
stdlib source); the benign-document set is 150 more such documents. That
pair is the one that decides, because it is what L2 reads in production.

| Set | PG2 86M @0.5 | **Horizon small @0.7** | DeBERTa v2 @0.5 | PIGuard @0.5 |
|---|---|---|---|---|
| Benign documents flagged (of 150) | 0 | **3** | 29 | 67 |
| Internal attacks planted in documents (of 39) | 4 | **21** | 13 | 34 |
| ... at a threshold flagging 2 of 150 benign documents | 9 | **19** | 0 | 3 |
| deepset attacks planted in documents (of 40) | 5 | **12** | 9 | 36 |
| Multilingual attacks planted in documents (of 5) | 1 | **5** | 0 | 2 |
| Internal corpus, attacks (of 39) | 8 | **36** | 30 | 27 |
| Internal corpus, benign flagged (of 9) | 1 | **0** | 3 | 3 |
| Multilingual attacks / benign counterparts flagged (of 5 each) | 1 / 0 | **5 / 0** | 5 / 4 | 2 / 2 |
| deepset/prompt-injections test split | 8/60, 0/56 FP | **25/60, 0 FP** | 22/60, 0 FP | 40/60, 0 FP |
| xTRam1/safe-guard test | 337/650, 2/1410 FP | **452/650, 12 FP** | 550/650, 2 FP | 400/650, 73 FP |
| jackhhao jailbreak, all rows (in Horizon's and DeBERTa's training data) | 624/666, 1/640 FP | **520/666, 3 FP** | 559/666, 4 FP | 649/666, 8 FP |
| Throughput vs Prompt Guard 2, median of 3 rotated runs | 1x (620 tok/s) | **2.4x** | 1.0x | 1.0x |

Horizon is the only model that separates attacks from benign documents at
all. DeBERTa and PIGuard score almost any instruction-shaped text near 1.0:
holding either to Horizon's false-positive rate takes a threshold above
0.99, where they catch next to nothing. PIGuard's paper is about reducing
exactly that over-defense, on its own short-prompt benchmark; on retrieved
documents it is the worst of the four. Both look good on direct-prompt sets
(DeBERTa leads safeguard), which is why a direct-prompt benchmark does not
transfer to L2. The multilingual pairs show the other failure: DeBERTa
flags four of the five benign counterparts, so it is flagging the language.

Horizon misses three internal attacks (`config-operator-runbook`,
`meta-already-cleared-upstream`, `role-verdict-in-character-game` at
0.66), and Prompt Guard 2 misses all three too. Its training data includes
the deepset train and jackhhao splits, so those rows flatter it; the
planted sets and the internal corpus are ours.

0.7 rather than 0.5: at 0.5 it flags 8 of the 150 benign documents and
catches 24 planted attacks; at 0.7, 3 and 21. Five of the eight benign
documents score between 0.5 and 0.7, so the cut sits in a crowded band
(three more score 0.77 to 0.97).

Until #353 this table reported #350's figures (26/39 planted, 2/150 benign)
from Horizon's own published ONNX in a separate harness. Its logits differ
from our export's by up to 0.43; the figures above are what production runs.
Its 2.9x throughput was raw ONNX on one window size; through `classify()`
on 4 threads it is 2.4x.

PIGuard's head is a Linear on the first token with no pooler, and its
checkpoint still carries pooler weights, so a stock DeBERTa export loads it
and scores wrong without an error. `export_l2_model.py --head cls-linear`
builds that head itself instead of running the repo's remote code; its
logits matched the reference within 1e-5.

**Candidates not measured** (surveyed on Hugging Face, 2026-10-03), so the
next pick starts from a list rather than a search:

| Model | Why not measured |
|---|---|
| `qualifire/prompt-injection-sentinel` | Gated, non-standard license; measure it once shipping it is cleared. |
| `ibm-granite/granite-guardian-3.3-8b` | An 8B LLM judge: an L3 candidate, not L2. |
| `meta-llama/Prompt-Guard-86M` (v1) | Superseded by Prompt Guard 2, which ships. |
| `protectai/deberta-v3-base-prompt-injection` (v1), `deepset/deberta-v3-base-injection`, `fmops/distilbert-prompt-injection` | Older generations of the DeBERTa family measured above. |
| `nvidia/NemoGuard-JailbreakDetect`, `katanemo/Arch-Guard`, `testsavantai/prompt-injection-defender-base-v0`, `Aira-security/FT-Llama-Prompt-Guard-2` | No stated license, or under 500 downloads. |

Lakera Guard is an API, not a local model.

**Trying another model.** Export it in the model-builder image with
`scripts/export_l2_model.py` (pinned revision, manifest naming the malicious
outputs and threshold), mount the directory and set `CLASSIFIER_MODEL_PATH`.
Score it with `--l2-only` above, then run `tests/test_l2_integration.py`
against it with `TRENTINA_REQUIRE_L2_MODEL=1`; a model with no recorded
expectations runs only the benign checks until its row is added.

## L2 obfuscation gate (#359)

A model-selection gate, run before an L2 model ships. L2 reads the arrived
bytes once (the [Layer contract](defense-pipeline.md#layer-contract)), so
a model that a zero-width split, a fullwidth letter or an encoding blinds
gets no help from the pipeline. `benchmarks/l2_obfuscation.py` classifies
every corpus attack plain and under six transforms, and fails any transform
that loses more than `--max-drop` (default 1) detections against plain.

```bash
CLASSIFIER_MODEL_PATH=<export> uv run python benchmarks/l2_obfuscation.py
```

2026-10-04, 44 attacks, each model at its own threshold:

| transform | Horizon small | Prompt Guard 2 86M |
|---|---|---|
| plain | 41 | 9 |
| zero-width, every letter | 41 pass | 0 FAIL |
| zero-width, mid-word | 41 pass | 14 pass |
| soft hyphens | 41 pass | 0 FAIL |
| fullwidth | 41 pass | 1 FAIL |
| base64 | 44 pass | 0 FAIL |
| Unicode tag characters | 41 pass | 1 FAIL |

Prompt Guard 2's failures are why L2 used to read L1's normalized copy as
well. Horizon needs no such help, and the second pass was retired.

## L1 briefing ablation

L1 reaches the verdict two ways: its own refusal at high or critical
risk, and L3's briefing, which names its counts by type. The second is
measured by `benchmarks/l1_briefing.py`, which runs real L1 and L2 on every
payload, then L3 with the production briefing (`full`) and with L1's
findings emptied (`ablated`). Each arm gets three calls and a majority vote.
The payloads are the semantic corpus, its attacks and benign cases under the
six obfuscation transforms, and the L1 pattern cases.

```bash
CLASSIFIER_MODEL_PATH=<export> TRENTINA_MODEL_PROVIDER=openrouter \
OPENROUTER_API_KEY=... uv run python benchmarks/l1_briefing.py --json rows.json
```

2026-10-04, 0.56.0, Horizon small at 0.7, `gemini-2.5-flash-lite`. The run
covered 502 payloads; L1 fired on 241, and only those have an ablated arm.

| | attacks (194 compared) | benign (47 compared) |
|---|---|---|
| L3 flagged with the briefing, not without | 2 | 4 |
| L3 flagged without the briefing, not with | 1 | 6 |
| verdict decided by L1's refusal alone | 2 | 29 |

16 of 502 payloads split across L3's own three calls.

- **The briefing does not measurably change L3.** It flipped 13 of 241
  payloads, in both directions, and that is inside L3's own run-to-run
  disagreement.
- **L1's refusal is what changes outcomes.** It caught 2 zero-width
  attacks that L2 and L3 both passed. It also refused 29 benign texts
  carrying zero-width or tag characters that both other layers cleared,
  because four invisible characters is already high risk.
- **L1 did not count two obfuscations when this ran.** Its patterns read
  through text spaced out with soft hyphens or set in fullwidth letters: a
  known directive still matched, but neither obfuscation was a finding in
  itself. On this semantic corpus L1 fired on the same 2 of 44 attacks with
  and without them. Both are counted since 0.58.0 (#363). L2 reads through
  both.
- **Elsewhere:** L2 flags every benign payload wrapped in base64 (14 of 14),
  and L3 flags 16 of the 48 L1 near-miss lines. L1 fires on none of
  those, so both arms are the same.

The benign transforms are synthetic: real benign text rarely carries a
zero-width character in every word. The 14-case benign corpus moves in 7%
steps.

## Unpack stage (#367)

The unpack stage (`unpack/scan.py`) builds what the layers read: canonical
base64 decoded in place, binary labelled by type. Three measurements set
its rules, all on 2026-10-04 with the default L2 at 0.7.

**Where L2 starts reacting to binary.** `benchmarks/l2_blob_length.py`
scores blobs by length and kind. Its synthetic tables (a blob alone, or in
one benign paragraph) overstate short blobs: a bare 32-character hex digest
is flagged every time, yet commit lists are not. The shapes ops output
actually carries set the floor:

| payload | label | score |
|---|---|---|
| git log, 5 commits | BENIGN | 0.070 |
| commit list JSON, 10 SHAs | BENIGN | 0.004 |
| app config, 44- and 24-char keys | BENIGN | 0.474 |
| docker config.json auth (56 chars) | BENIGN | 0.012 |
| seed, 64 chars | BENIGN | 0.692 |
| SRI integrity hash (64 chars) | MALICIOUS | 0.916 |
| SSH public key (~380 chars) | MALICIOUS | 0.991 |
| k8s Secret with a TLS key | MALICIOUS | 0.963 |

So binary is labelled from 64 characters, and hex digests up to SHA-512's
128 stay verbatim.

**Decoded text carries no marker.** Each of the 14 benign corpus texts
was classified as `Note: <marker><text>`:

| marker | benign flagged | attacks flagged (of 44) |
|---|---|---|
| none | 1 | 42 |
| `[base64 → text] ` | 4 | 43 |
| `[decoded] ` | 6 | 43 |
| `(decoded from base64:) ` | 5 | 43 |
| `[base64-decoded] ` | 8 | 43 |

A bracketed annotation reads like injection framing to the classifier. L3
learns what was decoded from its briefing instead. Labels for binary, in
parentheses, stayed at the benign baseline (0 to 3 of 42 placements across
wordings, against 1 to 3 for the plain text around them).

**Before and after, the base64 transform of the corpus** (L2 only):

| | L2 on the raw blob | L2 on the unpacked text |
|---|---|---|
| 14 benign texts | 14 flagged | 1 flagged |
| 44 attacks | 44 flagged | 42 flagged |

The 1 benign and 42 attacks match what L2 flags on the same texts with no
encoding at all, so the unpacked text reads like plain text to L2.

**The whole pipeline**, rerun with `benchmarks/l1_briefing.py` on lotor
(L3 `gemini-2.5-flash-lite`, three calls a payload, majority vote). Each
cell counts payloads refused by L1, L2 or L3:

| base64 transform | 0.56.0, raw blob | 0.57.0, unpacked |
|---|---|---|
| 14 benign texts refused | 14 | 2 |
| 44 attacks refused | 44 | 43 |

0.56.0 refused every base64 attack because L2 refused every blob, harmless
ones included. 0.57.0 refuses what the decoded text says. The attack it
lets through is one that L2 and L3 also pass when it is not encoded.

**What may be labelled.** A label means no layer reads the token's
characters, while an agent reading the raw delivery does. So binary an
agent cannot open (a key, an executable, random bytes) is labelled only
when every 64-character window of the token reads as noise. That needs
4.8 bits of entropy per character, and less than half of the window in
word-shaped letter runs:

| 64-character windows | entropy | word-shaped share |
|---|---|---|
| random base64 | 4.91 at the least | 0.58 at the most (0.36 at the 99th percentile) |
| spaceless English, corpus payloads | 4.72 at the most | 0.08 to 1.00, median 0.92 |
| spaceless English, words of four letters or fewer | n/a | 0.58 at the least |

Without the test, `MIIB` followed by an instruction written without
spaces decodes to a DER signature and would have been read as
`(DER certificate or key)`. An image, PDF or archive is labelled
regardless, because that label is the `binary_unread` refusal.

## L1 stage false positives (#363)

`benchmarks/l1_false_positives.py` runs L1 over real text and reports every
counter that fired, per file or per `--chunk N` lines. It is how a new L1
stage earns its place in `suspicious_detections`: a counter that fires on
ordinary operations text refuses ordinary calls under block (#204).

```bash
uv run python benchmarks/l1_false_positives.py docs src
journalctl -n 40000 --no-pager | uv run python benchmarks/l1_false_positives.py --chunk 200 -
```

Result for the stages added in 0.58.0 (2026-10-05):

| Text | Payloads | New counters that fired |
|---|---|---|
| The corpus: 44 attacks, 14 benign, 48 near-misses | 106 | none |
| A production host's journal, 40,000 lines in 200-line payloads | 200 | none |
| This repository's `docs/` and `src/` | per file | `forgery_gateway_verdicts` in `gateway/router.py`, `reserved.py` and `CHANGELOG.md`; `forgery_tool_calls` in the demo transcript; `addressed_ai_addressed_lines` in `l1/addressed.py` and the demo page |

Every hit in the repository is a file that writes the thing counted: the
gateway's own marker code, a transcript of a tool call, a detector's own
examples, a demo injection. One of them, `l1/addressed.py`, moves from
medium to high risk on its own docstring. A detector's source reads as what
it detects.

On the positive side, the corpus's 48 attack lines put through each
transform are counted as follows (`tests/test_l1_stages.py` holds the
floor): soft hyphens 47, fullwidth 43, Cyrillic lookalikes 45, ROT13 36,
reversed 36, and 20 each for backslash, character-reference and percent
escapes. The escape counter needs an instruction word in the decoded line,
and the ciphered one a full directive match.

L1 costs about 1.65 s per megabyte with the new stages. The ciphered check
adds roughly 45% to the directives stage.

## Redact's extraction input (#360)

Until 0.57.1 redact's extraction turn read a copy L1 had normalized. This is
the measurement that retired it (`benchmarks/redact_input.py`, 2026-10-05,
`google/gemini-2.5-flash-lite` through OpenRouter, the default L2). Each
corpus payload sits inside a fixed carrier notice and redact is asked to
summarize it, twice per input:

- **judged**: the unpacked delivery, the text L1, L2 and L3 detect on.
- **copy**: that text after L1's normalizing stages.

The 44 attacks and 14 benign texts run plain and under the six transforms of
the obfuscation gate. On 300 of the 406 payloads the two inputs differ; on
the rest L1 normalizes nothing and they are the same string.

| where the inputs differ (600 calls each) | judged | copy |
|---|---|---|
| delivered with an attack artifact | 22 | 22 |
| delivered with both of the carrier's facts | 532 | 515 |

An artifact is anything L1 counts in a delivered string, a URL from the
payload, or 40 characters of the attack verbatim. Every one of the 44 found
was the last kind, in both arms: no delimiter, invisible character, encoded
blob or payload URL was delivered from either input. The copy bought no
safety and cost 17 correct answers, so it was removed and redact reads what
was judged.

The same run shows what neither input fixes: a summary can quote a sentence
of the attack and pass the output check and turn 3. That happened in 29 of
876 calls on the judged text, attacks only.

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
