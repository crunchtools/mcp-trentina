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

### Stats
- quarantine_stats

### Gateway admin
- cache_flush — flush tool-list caches (all or one backend)
- reconnect_backend — reset one backend's circuit breaker + re-probe after it restarts, without restarting the gateway

## Development

```bash
uv run ruff check src tests    # Lint
uv run mypy src                # Type check
uv run pytest -v               # Test
podman run --rm -v .:/repo:Z quay.io/crunchtools/gourmand:latest --full /repo  # Slop detection
podman build -f Containerfile . # Container
uv run python benchmarks/provider_benchmark.py  # L3 detection benchmark across providers — see docs/benchmark.md
```

## Architecture

- `sanitize/` — Layer 1: 7-stage deterministic sanitization pipeline
- `quarantine/` — Layer 2: Q-Agent (Gemini REST via httpx, NO SDK, NO tools)
- `tools/` — Tool implementations called by server.py wrappers
- `database.py` — SQLite blocklist for cumulative detection memory
- `gateway/` — Per-consumer MCP gateway proxy with tool allowlists, parameter guards, and defense pipeline
  - **Parameter guards**: per-tool argument validation with allow/deny value patterns — see `docs/gateway-design.md`
