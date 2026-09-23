# mcp-trentina-crunchtools

Secure MCP server for quarantined web content extraction — two-layer defense against prompt injection.

## Quick Start

```bash
uv sync --all-extras
uv run mcp-trentina-crunchtools
```

## Environment Variables

- `GEMINI_API_KEY` — Required for Layer 2 (Q-Agent)
- `QUARANTINE_MODEL` — Gemini model for Q-Agent (default: gemini-2.5-flash-lite)
- `QUARANTINE_SEARCH_MODEL` — Gemini model for L0 search grounding (default: gemini-2.5-flash; must support google_search)
- `QUARANTINE_FALLBACK` — "layer1" (default) or "fail"
- `QUARANTINE_MAX_CONTENT` — Max chars to Q-Agent (default: 100000)
- `QUARANTINE_DB` — SQLite blocklist path (default: ~/.local/share/mcp-trentina/trentina.db)
- `TRENTINA_PERIMETER_DB` — perimeter verdict store, a SEPARATE database from the
  blocklist (default: `perimeter.db` beside `QUARANTINE_DB`). See `perimeter_db.py`
  for why it is its own file. Deleting it costs one slow restart and nothing else.
- `QUARANTINE_TRUST_CONFIG` — Trust allowlist JSON path
- `CLASSIFIER_THRESHOLD` — L2 malicious score cutoff (default: 0.5)
- `CLASSIFIER_MODEL_PATH` — Prompt Guard 2 ONNX dir (default: /models/prompt-guard-2-86m)
- `CLASSIFIER_MAX_TOKENS` — Max tokens L2 will scan; 0 disables the cap (default: 32768)
- `CLASSIFIER_THREADS` — ONNX intra-op threads; 0 uses the ONNX default of one per core (default: 4).
  Set it to match the container's `--cpus`; threads beyond that quota contend and slow scans down.

## onnxruntime telemetry

`ORT_DISABLE_TELEMETRY=1` is set in the Containerfile and defaulted in
`quarantine/classifier.py` before the lazy `import onnxruntime`. Left on,
onnxruntime's init reads `/etc/machine-id` and `/proc/cpuinfo`, reads
`/etc/os-release` four times, writes `/tmp/mat-debug-1.log`, and creates a
session file at `/tmp/.ses`. Disabling leaves only the `/sys/class/drm` and
`/sys/class/accel` probes it needs to choose an execution provider.

The same code path causes an import-time segfault in a shell-less image (see
the Containerfile's `/etc/machine-id` note). Both mitigations are in place;
either alone prevents the crash.

## Endpoints

- `GET /health` — unauthenticated liveness probe returning `{status, classifier, profiles}`.
  A timeout here means the asyncio event loop is blocked, not merely that a
  backend is slow.

## Layer 2 scanning limits

`classify()` slides a 512-token window at stride 256, so cost grows linearly
with input length. Two rules keep that bounded:

- Input is capped at `CLASSIFIER_MAX_TOKENS`. Past that the result carries
  `truncated=True`. The default sits above what `QUARANTINE_MAX_CONTENT`
  (100k chars ≈ 28k tokens) can produce, so the two limits never fight.
- A truncated scan of an **untrusted** source raises `UnscannableContentError`
  rather than reporting BENIGN — `safe_*` tools fail closed. The `quarantine_*`
  and `scan_*` tools report the partial scan as a warning instead, matching
  their existing proceed-with-warnings contract.

Async callers must use `classify_async` / `classify_guarded`. Calling the
synchronous `classify()` from a coroutine blocks the event loop for the whole
scan and takes the gateway down with it.

## Tools

### Safe (Layer 1 only)
- safe_fetch, safe_read

### Quarantine (Layer 1 + Layer 2)
- quarantine_fetch, quarantine_read, quarantine_scan
- quarantine_scan_dir — scan a directory for Python module shadowing attacks (e.g. struct.py replacing stdlib struct)

### Stats
- quarantine_stats — role-scoped like the gateway admin tools below: an agent
  profile gets its own audit rows, its own detections and the defense settings
  it runs under; an operator gets the gateway.

### Gateway admin

All four are scoped by the calling profile's `role` (`gateway/scope.py`, and
the Roles table in `docs/profiles.md`). `role: agent` — the default — sees and
acts on its own slice; `role: operator` holds the gateway. Refusals name
nothing, so a backend in another profile is refused exactly like one that does
not exist. Standalone (no gateway registered) is single-tenant and therefore
operator; a live gateway with no bound caller is refused.

- cache_flush — flush tool-list caches. Agent: its own backends and aggregate.
  Operator: every cache. A name is resolved by EXACT name, never by substring
  over cached URLs — that is how `gw` used to reach `gw-work` and
  `gw-personal` both.
- reconnect_backend — reset one backend's circuit breaker + re-probe after it
  restarts, without restarting the gateway. Agent: a backend in its own
  profile, with the tool count that profile would actually see. The breaker is
  keyed by URL, so healing it heals it for every profile sharing that URL —
  that is the point of the tool, not a leak.
- reload_profiles — re-read `profiles.yaml` and apply it. Nothing else applies
  a profile edit: the router filters from the `Profile` objects loaded at
  startup, and `cache_flush`/`reconnect_backend` rebuild that aggregate from
  the same in-memory objects, so they look like they worked and change nothing.
  Validates the whole file before swapping (a bad edit keeps the running
  config) and leaves the perimeter verdict cache alone so nothing is re-judged.
  Agent: applies its own section only, and cannot apply a change to its own
  `role`. Operator: the whole file, plus what it could not apply —
  `llm_providers`, `matrix`, and ingress routes bind at startup.

## Development

```bash
uv run ruff check src tests    # Lint
uv run mypy src                # Type check
uv run pytest -v               # Test
podman run --rm -v .:/repo:Z quay.io/crunchtools/gourmand:latest check /repo  # Slop detection
# Container image: built by GHA (.github/workflows/container.yml), never locally —
# the model-export stage needs a gated HF credential held only in CI. Push and let
# the pipeline build it.
uv run python benchmarks/provider_benchmark.py  # L3 detection benchmark across providers — see docs/benchmark.md
```

## Architecture

- `l1/` — Layer 1: the 7-stage deterministic pipeline that builds the SCAN VIEW,
  plus module shadow detection. It does not make content safe — it normalizes a
  copy so L2 and L3 have something stable to judge, and counts what it found.
  Called `sanitize/` until 0.24.0.
  - `shadows.py` — Python stdlib module shadow detection and obfuscation scanning
- `quarantine/` — Layer 2: Q-Agent (Gemini REST via httpx, NO SDK, NO tools)
- `tools/` — Tool implementations called by server.py wrappers
- `database.py` — SQLite blocklist for cumulative detection memory
- `perimeter_db.py` — the perimeter's own store, deliberately a second database:
  verdicts `defend()` reached, so a restart does not re-judge ~210 tool
  descriptions through all three layers before the first `tools/list` answers
- `channels.py` — the two driver roles, the ingresses a driver may be bound to,
  and what each ingress hands a driver (`Kind`). Guards decide admission;
  pre-processors transform outside the perimeter. Everything wired into a
  request path is one of the two.
- `jsonwalk.py` — the ONE JSON walk. There were two hand-maintained copies
  until #167; `tests/test_full_is_defend_json.py` proves they agreed, which is
  what made deleting one safe.
- `preprocess/` — Payload transformation, OUTSIDE the perimeter. May subtract
  but never absolve: it drops, collapses, normalizes and restructures, and
  everything it emits still crosses `defend()` as untrusted. Reduction is the
  common case, not the contract. Two INPUT SHAPES, not two roles: most are
  `str -> str`; `select.py` and `matrix.py` take parsed JSON and return the
  strings worth reading (`view.py`'s `DocumentProcessor`). A driver may read
  less than its call site delivers, and then it accounts for every byte it
  declined.
  - `petit.py` — record grouping via the `petit-log-crunchtools` package
    (petit itself, https://github.com/crunchtools/petit). Picks no driver and
    no stopword file: petit 3.2.0 made a hash driver declare its own
    normalization, so the policy lives with the format that needs it. Needs
    >= 4.1.1, where framing made the unit a RECORD rather than a line — the
    fingerprint cap is now `max_record_chars` INSIDE the library, because
    capping lines here cut records mid-JSON and silently disabled grouping.
    Samples are selected by `sample_spans`, so what is delivered is the
    original bytes; a record's first line is often just `{`.
  - `structured.py` — JSON. Fingerprints ARRAY ELEMENTS in element-index
    space and emits valid JSON, which is why petit does not replace it:
    petit reports positions as source LINE ranges and exposes group
    membership only for samples, so neither a minified array nor a
    per-element account is expressible through its API.
  - `email.py` — mail. Collapses quoted reply chains and strips signatures;
    leaves repeated footers to petit, which is what `chain` is for. Rewrites
    the thread, where petit's `EmailHash` only fingerprints its skeleton.
- `gateway/` — Per-consumer MCP gateway proxy with tool allowlists, parameter guards, and defense pipeline
  - **Parameter guards**: per-tool argument validation with allow/deny value patterns — see `docs/gateway-design.md`
  - `drivers.py` — the ONE registry. A configured name becomes a driver, for
    either role, with one channel lock and one parity test. Two registries
    here is what left the pre-processor table with no channel lock at all.
  - `transform.py` — the pre-processor call site on the tool path (was
    `reduce.py`; the contract is transformation, not reduction).
  - `selection.py` — the call site on the Matrix path. Runs the document
    processor, degrades to reading everything if it raises, and turns coverage
    into the fields an operator reads.
