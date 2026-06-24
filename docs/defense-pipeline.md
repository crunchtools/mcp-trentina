# Three-Layer Defense Pipeline

Trentina runs untrusted content through three independent detection layers before it reaches your agent. Each layer catches attack categories the others miss. No single layer — structural, classifier, or LLM — covers everything.

## Why This Matters

Prompt injection is the critical vulnerability in agentic AI systems. An attacker plants instructions in content your agent reads — a web page, a Jira ticket, a Slack message, an email body — and the agent follows them because it can't distinguish data from instructions. The [Clinejection attack](https://grith.ai/blog/clinejection-when-your-ai-tool-installs-another) compromised ~4,000 developer machines through a prompt injection in a GitHub issue title.

The defense-in-depth approach means an attack has to evade three fundamentally different detection methods to succeed.

## The Three Layers

### Layer 1 — Deterministic Sanitization

A 7-stage pipeline that strips structural attack vectors before any model sees the content:

1. **HTML sanitization** — strips hidden divs, invisible iframes, CSS injection, script tags
2. **Unicode normalization** — removes zero-width characters, homoglyphs, bidirectional text overrides
3. **Encoded payload detection** — catches base64-encoded instructions, hex-encoded payloads
4. **Exfiltration URL stripping** — removes markdown image URLs that exfiltrate data via GET parameters
5. **LLM delimiter stripping** — removes fake `<|system|>`, `[INST]`, `<|im_start|>` delimiters
6. **Directive detection** — flags instruction-like patterns ("ignore previous instructions", "you are now")
7. **Metric collection** — counts what was stripped for audit and detection scoring

**Latency:** <10ms. **Cost:** Zero (no model calls). **Always runs.**

### Layer 2 — Prompt Guard 2 Classifier

Meta's Prompt Guard 2 86M model running on ONNX Runtime (CPU, no GPU required). Classifies content as `BENIGN` or `MALICIOUS` with a confidence score.

**What it catches:** Direct instruction overrides, system prompt manipulation, delimiter injection, role hijacking.

**What it misses:** Data exfiltration requests (syntactically identical to legitimate requests), social engineering (authority-based attacks that don't use injection language).

**Latency:** ~150ms (86M model, ONNX, CPU). **Cost:** Zero (runs locally). **Configurable threshold per profile.**

### Layer 3 — Quarantined LLM (Q-Agent)

A hardened Gemini Flash Lite instance that receives sanitized content and extracts the useful information while ignoring injected instructions. The Q-Agent is deliberately constrained:

- **No tools** — can't execute actions even if manipulated
- **No memory** — can't be poisoned across sessions
- **No SDK** — raw httpx calls to the Gemini REST API, no dependency surface
- **Small model** — less capable models are harder to socially engineer

**What it catches:** Social engineering, data exfiltration intent, authority-based attacks, subtle semantic manipulation — everything that requires understanding *meaning*, not just *pattern*.

**What it misses:** Nothing that gets past L1 and L2 (in practice). The Q-Agent's catch rate on attacks that evade both L1 and L2 is near 100%.

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
