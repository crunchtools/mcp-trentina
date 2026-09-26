# mcp-trentina-crunchtools Constitution

> **Version:** 1.2.0
> **Ratified:** 2026-09-22
> **Status:** Active
> **Inherits:** [crunchtools/constitution](https://github.com/crunchtools/constitution) v1.17.0
> **Profile:** MCP Server

This constitution establishes the core principles, constraints, and workflows that govern all development on mcp-trentina-crunchtools.

---

## I. Core Principles

### 1. Five-Layer Security Model

Every change MUST preserve all five security layers.

**Layer 1 — Credential Protection:**
- GEMINI_API_KEY stored as Pydantic SecretStr
- API key scrubbed from all error messages via errors.py
- Separate env file from mcp-gemini for cost isolation

**Layer 2 — Input Validation:**
- Pydantic models enforce strict data types with `extra="forbid"`
- URL scheme validation (http/https only)
- Path traversal prevention
- Content size limits enforced before processing

**Layer 3 — API Hardening:**
- TLS to Gemini REST API (mandatory)
- Timeouts on all outbound HTTP calls (web fetch and Gemini)
- Response size limits on web fetches (5 MB)
- Content truncation before Q-Agent (configurable, default 100K chars)

**Layer 4 — Dangerous Operation Prevention:**
- **EXCEPTION:** This server is a security gateway, not an API wrapper. It fetches and processes untrusted web content by design. Layer 4 compliance is achieved by ensuring the server itself never executes arbitrary code, never shells out, and limits filesystem access to read-only on text files.
- No shell execution or code evaluation
- No `eval()`/`exec()` functions
- No `safe_exec` tool — permanently out of scope (incompatible with MCP Server profile)
- File reading scoped to text files only — binary rejected, read-only, no writes

**Layer 5 — Supply Chain Security:**
- Weekly automated CVE scanning via GitHub Actions
- Hummingbird container base images (minimal CVE surface)
- Gourmand AI slop detection gating all PRs
- No google-genai SDK — architectural enforcement of Q-Agent quarantine

### 2. Three-Layer Defense

Every untrusted payload crosses three independent layers, with no off switch
per layer (see `docs/defense-pipeline.md`):

- **L1 (deterministic):** `l1/` counts obfuscation, hidden markup, encoded
  blobs, exfiltration URLs, delimiters and directives, and builds a normalized
  copy for L2. It never modifies what the agent receives.
- **L2 (classifier):** Prompt Guard 2, local ONNX (`quarantine/classifier.py`).
- **L3 (judge):** a quarantined LLM (`quarantine/agent.py`) — NO tools, NO
  memory, NO SDK, per-request canary.

The tool prefix (`block_`, `warn_`, `clean_`) decides what is delivered, never
which layers run. No text written by L3 reaches the agent: findings leave
the perimeter as closed-enum labels and scores only.

The L3 quarantine is enforced architecturally:
- Raw httpx REST calls to the provider (no SDK)
- No function declarations in API requests
- No memory beyond single request
- Structured JSON output via responseSchema

### 3. Two-Layer Tool Architecture

Tools follow a strict two-layer pattern:
- `server.py` — `@mcp.tool()` decorated functions that validate args and delegate
- `tools/*.py` — Async functions that orchestrate sanitization, Q-Agent, and database

Never put business logic in `server.py`. Never put MCP registration in `tools/*.py`.

### 4. SQLite Blocklist Integrity

The SQLite blocklist is write-accessible by deterministic code ONLY:
- The Q-Agent cannot write to the database
- Q-Agent output is parsed by deterministic code which decides whether to record
- This prevents a compromised Q-Agent from manipulating the blocklist

### 5. Trust Allowlist

Trust decisions are administrator-set, NOT agent-controlled:
- Server-side JSON config file
- An allowlisted source still runs all three layers; the allowlist changes
  what a finding costs, never whether a layer runs
- A compromised agent cannot override trust levels

### 6. Three Distribution Channels

Every release MUST be available through all three channels simultaneously:

| Channel | Command | Use Case |
|---------|---------|----------|
| uvx | `uvx mcp-trentina-crunchtools` | Zero-install, Claude Code |
| pip | `pip install mcp-trentina-crunchtools` | Virtual environments |
| Container | `podman run quay.io/crunchtools/mcp-trentina` | Isolated, systemd |

### 7. Three Transport Modes

The server MUST support all three MCP transports:
- **stdio** (default) — spawned per-session by Claude Code
- **SSE** — legacy HTTP transport
- **streamable-http** — production HTTP, systemd-managed containers

### 8. Semantic Versioning

Follow [Semantic Versioning 2.0.0](https://semver.org/) strictly.

---

## II. Technology Stack

| Layer | Technology | Version |
|-------|------------|---------|
| Language | Python | 3.11+ |
| MCP Framework | FastMCP | Latest |
| HTTP Client | httpx (app) + httpx2 (MCP transport) | Latest |
| Validation | Pydantic | v2 |
| HTML Parsing | beautifulsoup4 | Latest |
| HTML-to-Markdown | markdownify | Latest |
| Database | SQLite | Built-in |
| Q-Agent Backend | Pluggable provider drivers over raw httpx (Gemini, OpenAI-compatible incl. OpenRouter, Anthropic, Ollama) | gemini-2.5-flash-lite (spec 002) |
| Container Base | Hummingbird | Latest |
| Package Manager | uv | Latest |
| Build System | hatchling | Latest |
| Linter | ruff | Latest |
| Type Checker | mypy (strict) | Latest |
| Tests | pytest + pytest-asyncio | Latest |
| Slop Detector | gourmand | Latest |

---

## III. Testing Standards

### Mocked Tests (MANDATORY)

All tests use mocked httpx — no live API calls. Test categories:
- Sanitization unit tests (one file per module)
- Pipeline integration tests
- Q-Agent tests (mock Gemini responses, verify no function declarations)
- Mode tests: every family × mode runs every layer (test_mode_parity), gaps refuse or warn (test_mode_gaps)
- File read tests (binary rejection, size limits)
- Adversarial tests (injection vectors)

### Tool count assertion

`test_tool_count` MUST be updated whenever tools are added or removed.

### Python version coverage (MANDATORY)

Two rules, and they are not negotiable independently — the second only works
because the first bounds it.

1. **Everything that can run on the whole matrix MUST run on the whole
   matrix.** CI tests every Python version between the floor declared in
   `requires-python` and the newest supported release, inclusive. No gaps. A
   version admitted by `requires-python` but absent from the CI matrix is an
   untested claim, which is how a floor of 3.10 survived while being
   uninstallable (issue #100).

2. **Anything that can only run on one version MUST run on the NEWEST
   supported version** — the one the container ships. Some work genuinely
   cannot be parallelized across the matrix: it needs a credential only one job
   holds, it costs live API quota per run, or it executes inside the built
   image. That work does not get to pick a comfortable middle version. It runs
   where production runs, because a single-version test that is not testing
   production's interpreter is testing a configuration nobody deploys.

The newest supported version is therefore load-bearing in two directions: it is
the matrix ceiling AND the home for every single-version job. When a new Python
release is adopted, both move together — adding it to `classifiers` without
moving the single-version jobs violates this section.

Type checking is exempt from rule 2 and deliberately so. `python_version` in
`[tool.mypy]` selects which language semantics to check *against*, not which
interpreter runs; pointing it at the newest release would stop it catching code
that breaks on the floor, which is the opposite of the intent. It should track
the floor, and where a dependency's stubs make that impossible the config MUST
record the specific blocker.

---

## IV. Gourmand (AI Slop Detection)

All code MUST pass `gourmand check .` with **zero violations** before merge. Gourmand is a CI gate in GitHub Actions.

### Configuration

- `gourmand.toml` — Check settings, excluded paths
- `gourmand-exceptions.toml` — Documented exceptions with justifications
- `.gourmand-cache/` — Must be in `.gitignore`

### Exception Policy

Exceptions MUST have documented justifications in `gourmand-exceptions.toml`. Acceptable reasons:
- Standard API patterns (HTTP status codes, pagination params)
- Test-specific patterns (intentional invalid input)
- Framework requirements (CLAUDE.md for Claude Code)
- Security tool patterns (sanitization stage names, threat category labels)

Unacceptable reasons:
- "The code is special"
- "The threshold is too strict"
- Rewording to avoid detection

---

## V. Code Quality Gates

Every code change must pass through these gates in order:

1. **Lint** — `uv run ruff check src tests`
2. **Type Check** — `uv run mypy src`
3. **Tests** — `uv run pytest -v`
4. **Gourmand** — pre-commit hook, and `Code Quality (Gourmand)` in CI
5. **Gatehouse** — pre-commit hook on the staged diff, and `Gatehouse review`
   on every PR. Every finding gets a reply before merge — `fixed in <sha>` or
   `not a bug: <reason>` — enforced by the `Gatehouse triage` check
6. **Container Build** — push the branch; GHA builds it
   (`.github/workflows/container.yml`). Never build the image locally: the
   model-export stage needs a gated HuggingFace credential that only CI holds.

---

## VI. Container Conventions

- Use **Containerfile** (not Dockerfile) as the build file name.
- Base image: **Hummingbird** (`quay.io/hummingbird/python:latest`) for minimal CVE surface.
- Always `dnf clean all` after package installs.
- Required LABELs: `maintainer`, `description`.
- Required OCI labels:
  ```
  org.opencontainers.image.source=https://github.com/crunchtools/mcp-trentina
  org.opencontainers.image.description=Quarantined web content extraction with prompt injection defense
  org.opencontainers.image.licenses=AGPL-3.0-or-later
  ```

### Dual-Push CI Architecture

Container CI workflows MUST use two separate jobs:

1. **`build-and-push-quay`** — Builds and pushes to Quay.io. Includes Trivy security scan.
2. **`build-and-push-ghcr`** — Builds and pushes to GHCR. Uses `needs: build-and-push-quay` dependency. Gated with `if: github.event_name != 'pull_request'`.

---

## VII. Naming Conventions

| Context | Name |
|---------|------|
| GitHub repo | `crunchtools/mcp-trentina` |
| PyPI package | `mcp-trentina-crunchtools` |
| CLI command | `mcp-trentina-crunchtools` |
| Python module | `mcp_trentina_crunchtools` |
| Container image | `quay.io/crunchtools/mcp-trentina` |
| systemd service | `mcp-trentina.service` |
| HTTP port | 8019 |
| License | AGPL-3.0-or-later |

---

## VIII. Development Workflow

### Adding a New Tool

1. Add the async function to the appropriate `tools/*.py` file
2. Export it from `tools/__init__.py`
3. Import it in `server.py` and register with `@mcp.tool()`
4. Add mocked tests in `tests/`
5. Update the tool count in `test_tool_count`
6. Run all five quality gates
7. Update CLAUDE.md tool listing

### Adding a New L1 Stage

1. Create module in `l1/` implementing the stage function
2. Wire it into `_run_stages` in `l1/pipeline.py`, and add its stats to
   `PipelineStats`
3. Add unit tests covering normal input and adversarial vectors
4. Run every quality gate

---

## IX. Governance

### Amendment Process

1. Create a PR with proposed changes to this constitution
2. Document rationale in PR description
3. Require maintainer approval
4. Update version number upon merge

### Ratification History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-03-09 | Initial constitution |
| 1.0.1 | 2026-03-10 | Add Sections IV (Gourmand), VII (Development Workflow), VIII (Governance) |
| 1.0.2 | 2026-03-16 | Add Section VI (Container Conventions); renumber VI-VIII → VII-IX |
| 1.0.3 | 2026-09-20 | Python floor 3.10+ → 3.11+ (3.10 was uninstallable, issue #100); record httpx2 as the MCP transport client alongside httpx |
| 1.1.0 | 2026-09-20 | Add Section III "Python version coverage": full matrix from floor to newest, single-version jobs pinned to newest (production's version) |
| 1.1.1 | 2026-09-22 | Inherit crunchtools/constitution v1.16.0 (XVII: no real-world names, PII or private deployment topology); examples, tests and docs moved to its fictional roster (RT #1504) |
| 1.2.0 | 2026-09-24 | Inherit v1.17.0 (Gatehouse pre-commit hook + triage). Section 2 rewritten for the three-layer defense it has had since 0.10 — it still described a 7-stage stripping L1 and an L2 extraction agent (Gatehouse critical on #182, unanswered). Allowlist, quality gates and the L1 stage recipe corrected to match the code |
