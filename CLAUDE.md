# mcp-trentina-crunchtools

Secure MCP server for quarantined web content extraction — two-layer defense against prompt injection.

## Quick Start

```bash
uv sync --all-extras
uv run mcp-trentina-crunchtools
```

## Environment Variables

- `GEMINI_API_KEY` — Required for Layer 2 (Q-Agent)
- `OPENROUTER_API_KEY` — standalone key for `TRENTINA_MODEL_PROVIDER=openrouter`;
  a gateway profile uses `llm_keys.openrouter`. Model ids are OpenRouter's
  (`google/gemini-2.5-flash-lite`).
- `QUARANTINE_MODEL` — Gemini model for Q-Agent (default: gemini-2.5-flash-lite)
- `QUARANTINE_SEARCH_MODEL` — Gemini model for L0 search grounding (default: gemini-2.5-flash; must support google_search)
- `TRENTINA_REQUIRE_L2` / `TRENTINA_REQUIRE_L3` — default true: block and redact
  refuse when that layer is ABSENT. `false` turns absence into a warning; a
  partial read is never excused. `QUARANTINE_FALLBACK` was removed in 0.31.0
  and setting it fails startup.
- `QUARANTINE_MAX_CONTENT` — Max chars to Q-Agent (default: 100000)
- `QUARANTINE_DB` — SQLite blocklist path (default: ~/.local/share/mcp-trentina/trentina.db)
- `TRENTINA_PERIMETER_DB` — perimeter verdict store, a SEPARATE database from the
  blocklist (default: `perimeter.db` beside `QUARANTINE_DB`). See `perimeter_db.py`
  for why it is its own file. Deleting it costs one slow restart and nothing else.
- `QUARANTINE_TRUST_CONFIG` — Trust allowlist JSON path
- `TRENTINA_RATE_LIMIT` — "off" disables limiting on the unauthenticated OAuth
  write paths (default on). An incident escape hatch, not a setting.
- `TRENTINA_FORWARDED_ALLOW_IPS` — peer addresses whose `X-Forwarded-For` is
  trusted, forwarded to uvicorn. **Unset behind a proxy, every caller shares
  one rate-limit bucket** — the limiter keys on `scope["client"]`, which
  uvicorn only rewrites for a trusted peer. Startup logs which is in effect.
- `TRENTINA_MAX_REGISTRATION_BYTES` — `POST /register` body cap (default 8192)
- `TRENTINA_REGISTRATION_TTL_DAYS` — lifetime of a PROMOTED registration
  (default 90). A new one is provisional for an hour; a token exchange
  promotes it and every later exchange re-stamps it. See `gateway/oauth_store.py`.
- `TRENTINA_OAUTH_CULL_INTERVAL` — seconds between sweeps of the OAuth store
  (default 3600, floor 60). Nothing else removes an expired record: the store
  unlinks one only when something reads its key, and an abandoned flow never
  is read again.
- `CLASSIFIER_THRESHOLD` — L2 malicious score cutoff (default: 0.5)
- `CLASSIFIER_MODEL_PATH` — Prompt Guard 2 ONNX dir (default: /models/prompt-guard-2-86m)
- `CLASSIFIER_MAX_TOKENS` — Max tokens L2 will scan; 0 disables the cap (default: 32768)
- `CLASSIFIER_THREADS` — ONNX intra-op threads; 0 uses the ONNX default of one per core (default: 4).
  Set it to match the container's `--cpus`; threads beyond that quota contend and slow scans down.
- `TRENTINA_L2_CONCURRENCY` — L2 scans at once (default 2); each uses `CLASSIFIER_THREADS`.
- `TRENTINA_L3_CONCURRENCY_START` / `TRENTINA_L3_CONCURRENCY_MAX` — the adaptive
  L3 limiter's starting point and ceiling per (provider, model) (4 / 64). See
  `quarantine/limiter.py`: it grows until the provider throttles, then AIMD.
- `TRENTINA_L3_THROTTLE_BUDGET` — seconds a user-facing L3 call waits out 429s
  on one provider before falling back (default 20; the boot warm-up uses 300).

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

## Boot warm-up and L3 pacing (#216)

`gateway/warmup.py` runs from the FastMCP lifespan and builds every profile's
aggregate through `router.ensure_profile_build`, the same single-flight task a
client's `tools/list` joins. Descriptions within a backend are judged
concurrently (`scan_tool_list`); what paces them is the per-judge
`AdaptiveLimiter` wrapped around every `provider.generate` call via
`limited_generate`. Call `generate` through `limited_generate`, never
directly: a bare call is invisible to the limiter and competes with it blind.

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
- A truncated scan is never reported as BENIGN. block and redact refuse it
  (`modes.Gaps`), so they pass `fail_on_truncate=True` and skip the inference
  at the token count; flag scans the head and delivers with `l2_truncated`.

Async callers must use `classify_async`. Calling the
synchronous `classify()` from a coroutine blocks the event loop for the whole
scan and takes the gateway down with it.

## Tools

### Five tools, three modes, one policy (0.32.0; renamed 0.35.0)

Rules P1–P10 are in `docs/defense-pipeline.md` (Pipeline Flow); the decision
lives in `modes.py`, the tool-side path in `tools/judged.py`.

Tools: `fetch_tool`, `read_tool`, `dir_tool`, `content_tool`, `search_tool`.
Every call runs L1 ∥ L2 on the arrived bytes, then L3 briefed with both. The
`trentina_mode` ARGUMENT decides delivery, never detection:

- `block` — refuses a flag or any blocking gap. Allowlisted → redact instead.
- `flag` — bytes IDENTICAL to what arrived, `_trentina_warning` attached. A
  security-researcher grant; leave it out of agent policies.
- `redact` — L3 detect, extract (guided by `trentina_prompt`), verify; any
  objection refuses.

"Arrived" means arrived at the perimeter, AFTER pre-processing. Output is
minified by default (0.38.0): the `detect` pre-processor picks the minifier by
format (`preprocess/detect.py`), and takes undeclared text for HTML only when
no tag name in it is foreign to HTML, because `html` deletes `<a@b.c>` and
`Vec<String>`. `trentina_preprocess` is a switch (#183): `false` exact, `true`
minified, omitted the tool's default (`read` and any `preprocess_tools` entry
with `enabled: false` default to exact). Every tool accepts it; a proxied
tool's schema declares it only where `selectable`, the internal fetch, read
and content always. `required` is the floor it cannot remove,
and the one failure rule is: floor fails closed, minifying fails open. The
internal tools run it in `tools/preprocess.py` (the router skips
`transform_response` for them) with `INTERNAL_CHAIN`. Policy:
`preprocess/policy.py`; gateway side rides `modes_policy.py` like the mode.
Proxied conversion hands L1 the ORIGINAL's hiding counts (#229).

Tools are served under short names (`gateway/names.py`), tagged with a backend
only on collision, recorded in `tool_names` and never reassigned. Only
tools/list and tools/call see them; everything behind the edge uses the real
(backend, tool). A repeated `structuredContent` is dropped before the scan
(`router._drop_duplicate_structured`).

Until 0.32.0 the mode was the tool's NAME prefix (#193), so the agent chose
its own posture and nothing enforced it. Now the policy does:

- Gateway: `defense.modes` per profile (default `[enforcement]`).
  `gateway/modes_policy.py` STRIPS any `trentina_*` param a backend declares
  before the perimeter scan, INSERTS the gateway's after it (only when more
  than one mode is allowed), resolves an omitted mode to `enforcement` BEFORE
  checking it, and strips both args before forwarding. Every backend's tools
  get it — `redact` on a proxied response is real now (`scan_tool_response`).
  Internal tools receive the RESOLVED mode; admin tools (no declared
  `trentina_mode`) get nothing inserted.
- Standalone: `TRENTINA_MODE` / `TRENTINA_MODES`, both defaulting to block.
- Refusals carry `{reason, mode, flagged_by|gaps, alternatives}` —
  JSON-RPC `error.data` for web tools, `_trentina_refusal` for proxied ones.
  Flagged → `redact` only, NEVER `flag`; gap-only → `flag`.

No text written by L3 reaches an agent: finding types are a closed enum
(`prompts.FINDING_TYPES`).

NOTE: `defense.enforcement` is the DEFAULT mode and accepts only `flag` and
`block` — a call that omits the mode carries no extraction prompt.

`warn`/`clean`, the pre-0.35.0 names (#200), were removed in 0.36.0; a
profile or call still using one is refused like any unknown mode. The names are OpenRouter's guardrail actions; our `redact` is an L3
rewrite, not their span substitution. Precedence: block > redact > flag.

### Stats
- quarantine_stats — role-scoped like the gateway admin tools below: an agent
  profile gets its own audit rows, its own detections and the defense settings
  it runs under; an operator gets the gateway.

### Operator profile / service identity (#138)

Trentina is AI-native: an Operator agent installs and configures it, and
`role: operator` is that agent's seat (`docs/operator.md`). At most one per
file, and it must hold `llm_keys` for its own provider (`loader._check_operator`).
The gateway's own model calls — compression, perimeter L3 over tool
descriptions, anything added later — run AS the operator via
`gateway/service.py` (`service_context()` binds it; the Q-Agent resolves key and
model from the bound profile). No operator: env-global, logged at startup.
Verdict keys carry the judging (provider, model) except for the env default,
which keeps the pre-#137 spelling so persisted verdicts stay reachable.

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

- `l1/` — Layer 1: the deterministic pipeline, plus module shadow detection.
  It does not make content safe — it counts what it found and normalizes a
  COPY for L2 to read. `PipelineResult` carries exactly two strings and the
  names say who reads each: `content` is what the agent receives, byte-identical
  to what arrived, and what L2 and L3 detect on; `l2_input` is L1's normalized
  copy, which L2 reads AS WELL when L1 normalized anything, and which redact's
  extraction turn reads. L1 also takes a directory's stdlib-shadow counts
  (`ShadowStats`), merged in by the `dir` producer.

  There is no "scan view" and no "delivery view". Those names were retired in
  0.29.0 along with `sanitize`/`scanview`: a reader cannot tell from "scan
  view" which layer consumes it, and "sanitized" claimed the layer made
  content safe, which it does not and cannot. Layers are L1/L2/L3 in code and
  in prose, with no invented aliases.

  Called `sanitize/` until 0.24.0. FORMAT-AGNOSTIC since 0.28.0: one entry
  point, `run_l1`, which scans whatever it is handed. The `looks_like_html`
  sniffer and the second `build_scan_view_from_html` pipeline are gone (#172)
  — the sniffer keyed on a leading `<!DOCTYPE` or `<html>`, so an HTML
  FRAGMENT took the text path and identical bytes were defended two different
  ways. `defend()` no longer takes `is_html` either.
  - `hidden.py` — content-hiding fingerprints (`display:none`, off-screen
    positioning, same-colour text), counted on EVERY payload rather than
    behind a format guess. Tier 2 of the markup answer; tier 1 is
    `preprocess/html.py`, which removes the class outright. Counts only — the
    hidden text's words are what L2 should still read. Owns the predicate
    table that `preprocess/html.py` imports, so the converter that strips an
    element and the stage that counts one decide by one rule.
  - `shadows.py` — Python stdlib module shadow detection and obfuscation scanning
  - `unicode.py` — strips every invisible character from the L2 copy but
    COUNTS one only in the context an attack needs (#204): zero-width inside
    a Latin word, a lone ESC, a run of variation selectors. Whether L2 reads
    the copy too is `PipelineResult.l2_reads_both()`, keyed on what was
    stripped, never on the counts.
  - `directives.py` — the exact patterns, named after OpenRouter's guardrail
    (#201). Near-misses matter as much as hits: every pattern has an attack
    and a benign line in `tests/adversarial_corpus.py` (`L1_PATTERN_CASES`),
    kept out of `CORPUS` because that is the semantic L3 benchmark.
  - `evasion.py` — undoes scrambles, one-edit typos and character spacing,
    then asks the exact patterns again. A typo alone is never a detection.
- `quarantine/` — holds BOTH judging layers, which is why the directory name
  matches neither: `classifier.py` is L2 (Prompt Guard 2, local ONNX) and
  `agent.py` is L3 (Gemini REST via httpx, NO SDK, NO tools). CLAUDE.md called
  this "Layer 2: Q-Agent" until 0.29.0, which was simply wrong.
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
  - `html.py` — markup to Markdown. The only CONVERTER here, and the reason
    it is a default: conversion ELIMINATES the hidden-content class rather
    than detecting it, because Markdown cannot express `display:none`. Lived
    in `l1/html.py` behind the sniffer until 0.28.0. Declines what it cannot
    parse instead of asking whether anything "is HTML", so it sits in the
    chain permanently and no-ops on everything else. It transforms without
    existing to shrink, so configure it under `chain` — `best_of` selects on
    size and would discard it.
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
  - `ratelimit.py` — the token bucket and the ASGI guard on `/register`,
    `/authorize` and `/consent`. NOT on `/token`: that is reached with a code
    or refresh token this gateway issued, so it is not unauthenticated, and
    limiting it throttles a legitimate refresh for no gain. Reads the address
    from `scope["client"]` and never from a header — reading `X-Forwarded-For`
    here would hand an attacker a fresh bucket per request.
  - `oauth_store.py` — registration lifetimes and the sweep that enforces
    them. `PromoteOnExchange` is mixed into the provider because that class is
    defined inside a function, where every method counts against its
    complexity budget.
  - `consent_ui.py` — patches fastmcp's consent page on the way out (a
    double-submit explanation, a client-side submit guard). Fails soft: markup
    it does not recognize passes through unchanged.
  - **Parameter guards**: per-tool argument validation with allow/deny value patterns — see `docs/gateway-design.md`
  - `drivers.py` — the ONE registry. A configured name becomes a driver, for
    either role, with one channel lock and one parity test. Two registries
    here is what left the pre-processor table with no channel lock at all.
  - `schema_compact.py` — drops null branches, null defaults and `$schema`
    from served inputSchemas, AFTER the perimeter scan. Tighten-only, and a
    subset of the judged strings, so it changes no verdict. Per backend
    `compact_schemas`, default on.
  - `transform.py` — the pre-processor call site on the tool path (was
    `reduce.py`; the contract is transformation, not reduction).
  - `selection.py` — the call site on the Matrix path. Runs the document
    processor, degrades to reading everything if it raises, and turns coverage
    into the fields an operator reads.
