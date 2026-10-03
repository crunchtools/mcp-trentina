# mcp-trentina-crunchtools Constitution

> **Version:** 1.6.0
> **Ratified:** 2026-09-22
> **Amended:** 2026-10-03
> **Status:** Active
> **Inherits:** [crunchtools/constitution](https://github.com/crunchtools/constitution) v1.18.0
> **Profile:** MCP Server

This file holds what is specific to mcp-trentina. The fleet rules and the MCP
Server profile (five-layer security model, two-layer tools, distribution
channels, transport modes, quality gates, Gourmand, Gatehouse) apply at the
inherited version and are checked against this repo's files by
`constitution.yml`. They are not restated here.

## Security Model Specifics

- **Credentials:** `GEMINI_API_KEY` is a Pydantic `SecretStr`, scrubbed from
  every error message by `errors.py`, and kept in an env file separate from
  mcp-gemini's for cost isolation.
- **Input limits:** URL schemes are http/https only; path traversal is
  rejected; content size limits apply before processing; web fetches are
  capped at 5 MB, and every outbound call (web fetch and provider) times out.
- **Admission cap:** one cap before any inference, in L2's tokens: the
  smaller of L2's CPU budget and the Q-Agent's context window. Admitted
  content is read whole by every layer; `block` and `redact` refuse what is
  over the cap, and no layer is handed a truncated slice of content it was
  asked to judge (`flag` alone scans an over-cap payload's head, and says so).
- **Supply chain:** no google-genai SDK, which enforces the Q-Agent
  quarantine architecturally.

## Gateway Exception to Dangerous-Operation Prevention

This server is a security gateway, not an API wrapper: it fetches and
processes untrusted web content by design. Compliance with the profile's
dangerous-operation layer is achieved by the server itself never executing
arbitrary code, never shelling out, and limiting file tools to read-only text.

- No `safe_exec` tool, permanently: it is incompatible with the MCP Server
  profile.
- File reading is scoped to text files: binary is rejected, read-only, no
  writes. This governs the file tools, the paths an agent names. It does not
  govern state the process owns: the SQLite stores (blocklist, perimeter
  verdicts, OAuth, bridge mappings), the caches, and the Matrix bridge's
  crypto store and session, all written by deterministic code under the
  process's own configured data directory only: the blocklist's directory for
  the gateway, `BRIDGE_STORE_DIR` for the bridge (each its container's
  `/data`). The bridge's operator commands read that same store.
- The one read of a store the process does not own is `import-mautrix`: an
  operator-run command that opens another client's crypto store read-only,
  never reachable from a tool or an agent.

## Three-Layer Defense

Every untrusted payload crosses three independent layers, with no off switch
per layer (see `docs/defense-pipeline.md`):

- **L1 (deterministic):** `l1/` counts obfuscation, hidden markup, encoded
  blobs, exfiltration URLs, delimiters and directives, and builds a
  normalized copy for L2. It never modifies what the agent receives.
- **L2 (classifier):** a local ONNX prompt-injection classifier
  (`quarantine/classifier.py`). The model is an operator setting
  (`CLASSIFIER_MODEL`, #350): Horizon-Labs' prompt-injection-guard-small by
  default, Llama Prompt Guard 2 86M also shipped, each exported from a pinned
  revision with a manifest that states its polarity and threshold. A model
  an operator brings through `CLASSIFIER_MODEL_PATH` without a manifest
  loads only when every label in its `config.json` is a known benign or
  malicious name, at the 0.5 default. A model whose polarity cannot be read
  does not load; L2 is then absent, never guessed.
- **L3 (judge):** a quarantined LLM (`quarantine/agent.py`): no tools, no
  memory, no SDK, per-request canary.

The mode (`trentina_mode`, chosen per call within the profile's policy)
decides what is delivered, never which layers run. No text written by L3
reaches the agent: findings leave the perimeter as closed-enum labels and
scores only.

The L3 quarantine is enforced architecturally: raw httpx REST calls to the
provider, no function declarations in API requests, no memory beyond a
single request, structured JSON output via a response schema. Provider
drivers are pluggable (Gemini, OpenAI-compatible including OpenRouter,
Anthropic, Ollama); the default model is `gemini-2.5-flash-lite` (spec 002).

A new L1 stage is a module in `l1/`, wired into `_run_stages` in
`l1/pipeline.py` with its stats added to `PipelineStats`, and tested on
normal input and adversarial vectors.

## Blocklist Integrity

The SQLite blocklist is writable by deterministic code only. The Q-Agent
cannot write to it; its output is parsed by deterministic code, which decides
whether to record. A compromised Q-Agent therefore cannot manipulate the
blocklist.

## Matrix Bridge Credential Split

Matrix end-to-end encryption terminates in the bridge process, never in the
agent (spec 015). The split is structural, not a convention:

- The bridge process holds the upstream Matrix login and crypto store, no
  credential for the agent's homeserver, and shares no network with it.
- The gateway holds the appservice token for the agent's homeserver and no
  upstream Matrix credential.
- Every event that carries content crosses all three layers in both
  directions before it is written to either side. A redaction carries none:
  it names an event already judged, and its reason text is dropped rather
  than carried, so it is mirrored without a verdict.

## Trust Allowlist

Trust decisions are administrator-set in a server-side JSON config file, not
agent-controlled. An allowlisted source still runs all three layers; the
allowlist changes what a finding costs, never whether a layer runs. A
compromised agent cannot override trust levels.

## Python Version Coverage

Two rules, not negotiable independently; the second only works because the
first bounds it.

1. Everything that can run on the whole matrix MUST run on the whole
   matrix: every Python version from the `requires-python` floor to the
   newest supported release, inclusive, no gaps. A version admitted by
   `requires-python` but absent from the CI matrix is an untested claim,
   which is how a floor of 3.10 survived while being uninstallable
   (issue #100).
2. Anything that can only run on one version MUST run on the newest
   supported version, the one the container ships. Work that needs a
   credential only one job holds, costs live API quota, or runs inside the
   built image runs where production runs.

When a new Python release is adopted, the matrix ceiling and the
single-version jobs move together. Type checking is exempt from rule 2:
mypy's `python_version` selects the language semantics checked against and
should track the floor; where a dependency's stubs make that impossible the
config MUST record the specific blocker.

## Test Coverage Specifics

Beyond the profile's mocked tests: sanitization unit tests per module,
pipeline integration tests, Q-Agent tests that verify no function
declarations are sent, mode tests (every family x mode runs every layer in
`test_mode_parity`; gaps refuse or warn in `test_mode_gaps`), file-read tests
(binary rejection, size limits) and adversarial injection vectors.

## Container Builds Are CI-Only

The image is never built locally: the model-export stage needs a gated
HuggingFace credential that only CI holds. Push the branch and let
`.github/workflows/container.yml` build it.

## Gourmand Exception Reasons

Beyond the profile's acceptable reasons, security-tool vocabulary
(sanitization stage names, threat category labels) is an accepted
justification in `gourmand-exceptions.toml`.

## Instance

| Context | Name |
|---------|------|
| GitHub repo | `crunchtools/mcp-trentina` |
| PyPI package | `mcp-trentina-crunchtools` |
| Python module | `mcp_trentina_crunchtools` |
| Container image | `quay.io/crunchtools/mcp-trentina` |
| systemd service | `mcp-trentina.service` |
| HTTP port | 8019 |
| HTTP clients | httpx (application), httpx2 (MCP transport) |
| Extra stack | beautifulsoup4, markdownify, SQLite |

## History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-03-09 | Initial constitution |
| 1.0.1 | 2026-03-10 | Gourmand, Development Workflow and Governance sections added |
| 1.0.2 | 2026-03-16 | Container Conventions section added |
| 1.0.3 | 2026-09-20 | Python floor 3.10+ to 3.11+ (3.10 was uninstallable, issue #100); httpx2 recorded as the MCP transport client |
| 1.1.0 | 2026-09-20 | Python version coverage: full matrix from floor to newest, single-version jobs on newest |
| 1.1.1 | 2026-09-22 | Inherit v1.16.0 (XVII); examples, tests and docs moved to its fictional roster (RT #1504) |
| 1.2.0 | 2026-09-24 | Inherit v1.17.0. Three-layer defense rewritten to match the code (Gatehouse critical on #182); allowlist, quality gates and the L1 stage recipe corrected |
| 1.2.1 | 2026-09-25 | Q-Agent backend: pluggable provider drivers, default gemini-2.5-flash-lite since spec 002 |
| 1.3.0 | 2026-09-27 | The 100K-character truncation before the Q-Agent becomes one token admission cap (#225) |
| 1.4.0 | 2026-09-27 | File rule scoped to the file tools; process-owned state named. Matrix bridge credential split added (#162) |
| 1.4.1 | 2026-09-27 | Bridge operator commands read the bridge's own store; `import-mautrix` named as the one read of a foreign store |
| 1.5.0 | 2026-10-02 | Manifest under constitution v1.18.0: profile restatement removed, repo-specific security design kept under its own headings; the stale `block_`/`warn_`/`clean_` tool-prefix wording replaced by the per-call `trentina_mode` |
| 1.6.0 | 2026-10-03 | L2 is a pluggable local classifier (#350): Horizon-Labs prompt-injection-guard-small by default, Prompt Guard 2 86M selectable, polarity and threshold from a pinned-model manifest |
