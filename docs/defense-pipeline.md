# Three-Layer Defense Pipeline

Trentina runs untrusted content through three independent detection layers before it reaches your agent. Each layer catches attack categories the others miss. No single layer — structural, classifier, or LLM — covers everything.

## Two roles: guards decide, pre-processors transform

Everything Trentina wires into a request path is one of exactly two things. If you are adding a driver and it seems to be neither, it is one of them and you have not decided which yet.

**Guards make the final call on admission to the trust perimeter.** Nothing else does. There are three kinds and they are named here so that "what decides?" is answerable from the docs rather than from `git log`:

| guard | what it judges | where |
|---|---|---|
| **Parameter guards** | the *arguments* of a `tools/call`, after the tool-name allowlist and before the backend is contacted | `gateway/guards.py`, [parameter-guards.md](parameter-guards.md) |
| **Response guards** | the backend's *result*, after the call returns and before anything is transformed, scanned or relayed | `gateway/guards.py`, [response-guards.md](response-guards.md) |
| **The scanner** | content, through L1 → L2 → L3 below | `defense.py` — and `defend()` is the only entry point, enforced by `tests/test_defense_contract.py` |

A guard also decides **what it reads**. On a payload too large or too opaque to scan whole, the scanner's read policy (`scanview/`) selects which strings reach L1/L2/L3 and accounts for every byte it declined — coverage, a skip histogram by reason, and `low_scan_coverage` when it falls below the floor. That privilege belongs to guards because deciding how thoroughly to judge *is* a judgement.

**Pre-processors are everything before that.** They run outside the perimeter, their output is exactly as untrusted as their input, and everything they emit crosses the guards on the way in. They may decode, decrypt, reduce, summarize, normalize, split and reshape — the contract is transformation generally, not reduction (`preprocess/base.py`, and [token-routing.md](token-routing.md) for how they are configured).

### The line between them

One rule separates the roles, and it is the reason `scanview/` is guard machinery rather than a third kind of driver:

> **A pre-processor may never open a gap between what is scanned and what is delivered.** Its output is both. A driver that scans *less* than it delivers is a guard's read policy, never a pre-processor.

The two halves are opposite security readings of the same verb. What a pre-processor drops never reaches the agent *or* the scanner, which is what makes fingerprint-collision games pointless — colliding your payload into a collapsed group deletes it. An extractor is the inverse: the full original is delivered while a subset is scanned, so colliding into a skipped bucket would deliver your payload unscanned. One Protocol cannot honestly carry both, which is why each role gets its own, and why they share exactly one piece of wiring — the registry and channel lock in `gateway/drivers.py`.

Their failure modes point in opposite directions for the same reason. A pre-processor fails open to **delivering the original**; a read policy fails open to **scanning everything**. Both mean "on failure, do the thing that hides nothing."

## What crosses the pipeline

Everything entering through the gateway is judged at its ingress — the firewall model: filter where content enters, once.

- **MCP tool responses** from every remote backend: text blocks, resource text, and every string leaf of `structuredContent`, judged as one document (recorded as `source_type=tool_response`). Image blocks and binary blobs cannot be judged; their counts ride in the warning.
- **Tool definitions** on every `tools/list`: name, title, description, `inputSchema`, annotations — the MCP tool-poisoning channel (`tool_description`). Runs on post-compression text; a description the compressor rewrote is model output and gets unconditional L3.
- **Matrix**: `/sync` and room `/messages` responses, buffered and judged whole (`matrix_sync`). E2EE rooms are ciphertext on the wire; with `scan_view.decrypt` configured the proxy terminates Megolm to build the scan view and forwards the original ciphertext untouched, so the homeserver never sees plaintext and the agent still decrypts for itself. Decryption is read-only, additive and ephemeral — recovered plaintext exists only in the scan view. Without it, encrypted rooms are outside what the gateway can read, and the coverage gap is counted and reported rather than assumed.
- **LLM completions** through the proxy, judged post-stream (`llm_completion`).
- **Alert webhooks** (`alert`), and the standalone web tools (`safe_*`, `quarantine_*`).

**Enforcement is per profile** (`defense.enforcement`): `annotate` (default — content delivered intact with a `_trentina_warning`, every flag recorded for calibration), `block` (flagged responses refused; for autonomous agents), `extract` (Q-Agent rewrite; for interactive profiles). `TRENTINA_ENFORCEMENT_OVERRIDE=annotate` is the kill switch.

**Content is never silently modified.** L1 detects; it does not censor. What the agent receives is byte-identical to what entered the perimeter, or (under `block`) nothing plus the warning. The one transformation that remains is HTML→Markdown extraction in the fetch tools, which is their product, not a security edit.

## Why This Matters

Prompt injection is the critical vulnerability in agentic AI systems. An attacker plants instructions in content your agent reads — a web page, a Jira ticket, a Slack message, an email body — and the agent follows them because it can't distinguish data from instructions. The [Clinejection attack](https://grith.ai/blog/clinejection-when-your-ai-tool-installs-another) compromised ~4,000 developer machines through a prompt injection in a GitHub issue title.

The defense-in-depth approach means an attack has to evade three fundamentally different detection methods to succeed.

## The Three Layers

### Layer 1 — Deterministic Detection (the tripwire)

L1 produces two views of one payload and never modifies what the agent receives:

- **The delivery view** — the caller's text, untouched. A CVE ticket, a Nagios alert, or a security mail *discusses* attacks in the words attacks use; amputating those lines destroyed exactly the content an ops agent exists to read, and destroyed the evidence before the smarter layers could judge it.
- **The scan view** — the same text with obfuscation normalized away: zero-width characters removed, encoded blobs decoded and replaced with markers, fake `<|im_start|>`/`[INST]` delimiter tokens dropped, exfiltration image URLs defanged. **L2 reads this view**, so an attacker cannot blind the classifier with the very tricks L1 counts.

Detections (hidden HTML, unicode manipulation, encoded payloads, exfiltration URLs, LLM delimiters, directive patterns like "ignore previous instructions") feed three places: the risk score, the sidecar warning, and the L3 gate — **any suspicious L1 detection sends the full original to the Q-Agent**, whose briefing says explicitly that nothing was removed and that the flag may be an attack *or* legitimate security content: judge intent, not vocabulary.

**Latency:** <10ms. **Cost:** Zero (no model calls). **Always runs.**

### Layer 2 — Prompt Guard 2 Classifier

Meta's Prompt Guard 2 86M model running on ONNX Runtime (CPU, no GPU required). Classifies content as `BENIGN` or `MALICIOUS` with a confidence score.

**What it catches:** Direct instruction overrides, system prompt manipulation, delimiter injection, role hijacking.

**What it misses:** Data exfiltration requests (syntactically identical to legitimate requests), social engineering (authority-based attacks that don't use injection language).

**Latency:** ~150ms (86M model, ONNX, CPU). **Cost:** Zero (runs locally). **Configurable threshold per profile.**

### Layer 3 — Quarantined LLM (Q-Agent)

A hardened Gemini Flash Lite instance that receives the **original, unmodified content** (with L1's sidecar as its briefing) and judges or extracts while ignoring injected instructions. The Q-Agent is deliberately constrained:

- **No tools** — can't execute actions even if manipulated
- **No memory** — can't be poisoned across sessions
- **No SDK** — raw httpx calls to the Gemini REST API, no dependency surface
- **Small model** — less capable models are harder to socially engineer

**What it catches:** Social engineering, data exfiltration intent, authority-based attacks, subtle semantic manipulation — everything that requires understanding *meaning*, not just *pattern*.

**What it misses:** with the default `QUARANTINE_MODEL` (`gemini-2.5-flash-lite`), the Q-Agent's aggregate catch rate on attacks written to evade both L1 and L2 is 86% (see `benchmarks/results/`), not near-100% — and it drops to 33% on the `detector_meta` category (attacks targeting the detector itself). A stronger `QUARANTINE_MODEL` closes most of that gap; see `docs/benchmark.md` for per-model numbers before treating L3 as a reliable backstop.

**Latency:** 1-2s (Gemini round-trip). **Cost:** Gemini API tokens. **Optional per profile.**

## Coverage Matrix

Benchmarked against 105 test cases across 10 attack categories (Prompt Guard 2 22M vs 86M, ONNX Runtime, CPU):

| Attack Type | L1 (Structural) | L2 (Classifier) | L3 (Q-Agent) |
|-------------|-----------------|-----------------|--------------|
| Hidden div injection | **catches** | n/a (L1 strips it) | n/a |
| Zero-width obfuscation | **catches** | n/a (L1 strips it) | n/a |
| Base64 encoded payloads | **catches** | n/a (L1 strips it) | n/a |
| Markdown image exfiltration | **catches** | misses | n/a |
| Direct instruction override | partial | **catches** (100%) | catches |
| System prompt manipulation | partial | **catches** (90%) | catches |
| LLM delimiter injection | **catches** | catches (90%) | catches |
| Role/persona hijacking | misses | partial (80%) | **catches** |
| Social engineering | misses | misses (40%) | **catches** |
| Data exfiltration (action) | partial | misses (20%) | **catches** |

The key insight: classifiers are excellent at what they were trained for (instruction overrides) and categorically blind to what they weren't (social engineering, exfiltration). The Q-Agent covers the gap. No single model — classifier or LLM — handles everything.

## Configuration

Defense settings are configured per profile:

```yaml
profiles:
  myagent:
    defense:
      sanitize: true           # L1 — always cheap, default on
      classify: true           # L2 — Prompt Guard 2 86M
      classify_threshold: 0.5  # L2 confidence threshold
      quarantine: true         # L3 — Gemini Q-Agent
```

### L3 Cost Control

L3 is the only layer with non-trivial cost (Gemini API tokens). Two controls:

1. **Per-profile toggle**: `quarantine: false` disables L3 for that profile entirely
2. **Threshold gating**: L3 only fires when L2 flags content above the threshold — in steady state, L3 contributes near-zero latency and cost

Autonomous agents that process high volumes can run L1+L2 only (`quarantine: false`). Human-supervised agents can afford L3 since it only fires on suspicious content.

## Pipeline Flow

```
Content in → L1 sanitize → L2 classify → L3 Q-Agent (if triggered) → Content out
                                ↓
                          Score < threshold?
                          → Pass through with metadata sidecar
                          Score ≥ threshold?
                          → L3 re-extraction (quarantine mode)
                          → Block (safe mode)
```

The `safe_*` tools fail-closed on L2 detection. The `quarantine_*` tools warn and proceed, extracting content through L3. Both add detection metadata so the consuming agent can make informed decisions.

## Related

- [Blocklist](blocklist.md) — cumulative detection memory across sessions
- [Quarantine Tools](quarantine-tools.md) — how the defense pipeline is exposed as MCP tools
- [Per-Agent Profiles](profiles.md) — per-profile defense configuration
