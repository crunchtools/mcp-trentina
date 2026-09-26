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

A guard also decides **what it reads**. On a payload too large or too opaque to scan whole, a pre-processor selects which strings reach L1/L2/L3 and accounts for every byte it declined — coverage, a skip histogram by reason, and `low_scan_coverage` below the floor. The guard still makes the call; it is simply told what it is looking at.

**Pre-processors are everything before that.** They run outside the perimeter, their output is exactly as untrusted as their input, and everything they emit crosses the guards on the way in. They may decode, decrypt, reduce, summarize, normalize, split and reshape — the contract is transformation generally, not reduction (`preprocess/base.py`, and [token-routing.md](token-routing.md) for how they are configured).

### Where the line falls

One rule separates the roles:

> **A pre-processor never bypasses `defend()`.** Everything it emits is scanned. Whether the *delivered* bytes are its output or the untouched original is the **call site's** decision, not the driver's.

`gateway/transform.py` delivers what the chain returned. `gateway/matrix_proxy.py` forwards the upstream ciphertext, because the agent must decrypt for itself. Where the two differ, the call site accounts for the gap.

**Scanning something different from what you deliver is not an anomaly — it is how L1 works.** L1 normalizes a copy for L2 to read and delivers the original untouched, because a Nagios alert or a CVE ticket discusses attacks in the words attacks use.

An earlier revision of this page ruled the opposite: that a pre-processor may never open a gap between what is scanned and what is delivered, and used that to make scan-view extraction a separate kind of driver. The rule does not survive contact with L1, and the split it justified is gone. It is recorded here because the reasoning was plausible and someone will reconstruct it.

Failure modes point in whichever direction hides nothing. A text pre-processor that fails delivers and scans the **original**; one that selects what to read fails to reading **everything**. Same rule, different thing owned. The exception is a processor the call depends on: a profile's `required` floor, and anything an internal tool was asked to run, fail **closed** — the call is refused rather than handed something other than what was asked for.

The agent chooses its pre-processors per call with `trentina_preprocess`, within the profile's ceiling (plus a tool's own default, such as `html` on `fetch`) and above its floor ([Profiles](profiles.md#pre-processors-per-call)). The choice changes what is delivered, and so what is judged, never whether it is judged.

## What crosses the pipeline

Everything entering through the gateway is judged at its ingress — the firewall model: filter where content enters, once.

- **MCP tool responses** from every remote backend: text blocks, resource text, and every string leaf of `structuredContent`, judged as one document (recorded as `source_type=tool_response`). Image blocks and binary blobs cannot be judged; their counts ride in the warning.
- **Tool definitions** on every `tools/list`: name, title, description, `inputSchema`, annotations — the MCP tool-poisoning channel (`tool_description`). Runs on post-compression text; a description the compressor rewrote is model output and gets unconditional L3.
- **Matrix**: `/sync` and room `/messages` responses, buffered and judged whole (`matrix_sync`). E2EE rooms are ciphertext on the wire; with `preprocess.decrypt` configured the proxy terminates Megolm to build the L2 input and forwards the original ciphertext untouched, so the homeserver never sees plaintext and the agent still decrypts for itself. Decryption is read-only, additive and ephemeral — recovered plaintext exists only in the L2 input. Without it, encrypted rooms are outside what the gateway can read, and the coverage gap is counted and reported rather than assumed.
- **LLM completions** through the proxy, judged post-stream (`llm_completion`).
- **Alert webhooks** (`alert`), and the standalone web tools (`safe_*`, `quarantine_*`).

**The mode is per call, the policy per profile.** `defense.modes` lists what the agent may choose through `trentina_mode`, which the gateway inserts into every tool; `defense.enforcement` is the default an omitted mode resolves to — `flag` (content delivered intact with a `_trentina_warning`) or `block` (flagged responses refused). See [Profiles](profiles.md#content-modes). `TRENTINA_ENFORCEMENT_OVERRIDE=flag` is the kill switch, and beats the call's own choice.

`redact` cannot be the enforcement mode, because `enforcement` is the default an omitted `trentina_mode` resolves to, and a call that omits the mode carries no extraction prompt. It is available per call through `defense.modes` since 0.32.0: the call supplies `trentina_prompt`, which is what a proxied response lacked. `extract`, its pre-0.25.0 spelling, loads as `block`.

The PUSH paths set it themselves, because no agent is waiting to be asked: `alert_ingress.enforcement` defaults to `flag`, so a Nagios page forwards with the caution attached. The Matrix path has no setting on purpose — refusing a streamed `/sync` response breaks the client's sync loop rather than dropping a message.

**Content is never silently modified.** L1 detects; it does not censor. What the agent receives is byte-identical to what entered the perimeter, or (under `block`) nothing plus the warning. Transformation belongs to the pre-processors, which run OUTSIDE the perimeter and whose output crosses the pipeline like anything else — HTML→Markdown conversion is one of them, the fetch tool's default product rather than a security edit, and the agent may decline it with `trentina_preprocess: []` unless the profile requires it.

## Why This Matters

Prompt injection is the critical vulnerability in agentic AI systems. An attacker plants instructions in content your agent reads — a web page, a Jira ticket, a Slack message, an email body — and the agent follows them because it can't distinguish data from instructions. The [Clinejection attack](https://grith.ai/blog/clinejection-when-your-ai-tool-installs-another) compromised ~4,000 developer machines through a prompt injection in a GitHub issue title.

The defense-in-depth approach means an attack has to evade three fundamentally different detection methods to succeed.

## The Three Layers

### Layer 1 — Deterministic Detection

L1 counts, and never modifies what the agent receives:

- **What the agent receives** (`content`) — the caller's text, untouched. A CVE ticket, a Nagios alert, or a security mail *discusses* attacks in the words attacks use; amputating those lines destroyed exactly the content an ops agent exists to read, and destroyed the evidence before the smarter layers could judge it.
- **A normalized copy** (`l2_input`) — the same text with obfuscation undone: zero-width characters removed, encoded blobs decoded, fake `<|im_start|>`/`<|eot_id|>`/`[INST]` delimiters dropped, exfiltration image URLs (Markdown and HTML) defanged. L2 reads it *in addition to* the original whenever L1's normalizing stages fired (three zero-width characters can split Prompt Guard's tokens while L1 rates them only medium), and redact mode's extraction turn reads it.

Detections (hidden markup, unicode manipulation, encoded payloads, exfiltration URLs, LLM delimiters, directive patterns like "ignore previous instructions", and — for a directory — Python files that shadow the standard library) feed the risk score, the warning, and L3's briefing.

**L1 is format-agnostic.** It scans what it is handed and makes no judgement about a payload's type. Until 0.28.0 a `looks_like_html` sniffer chose between an HTML pipeline and a text one on a leading `<!DOCTYPE` or `<html>`; an HTML *fragment* — the shape most tool output carries — matched neither, so identical bytes were defended two different ways depending on their first few characters. The fork is gone. Markup is handled in two tiers instead:

- **Tier 1, conversion (`preprocess/html.py`).** Converting to Markdown does not detect hidden content, it removes the vocabulary that expresses it: Markdown has no `style` attribute, no `display:none`, no foreground/background pair. After conversion the attack class is absent rather than mitigated. The converter declines on anything it cannot parse, so it sits in the default chain and no-ops on everything that is not markup.
- **Tier 2, fingerprints (`l1/hidden.py`).** Conversion cannot be guaranteed to have run — the agent may ask for raw bytes, the converter may decline, or the text may merely embed markup. So an ordinary L1 stage counts hiding fingerprints (`display:none`, off-screen positioning, same-colour text, KaTeX `\color{white}`) on every payload and feeds the risk score.

#### Where these patterns come from

L1's directive, control-token, encoding and image-exfiltration patterns follow OpenRouter's published [prompt-injection guardrail](https://openrouter.ai/docs/guides/features/guardrails/prompt-injection), which is derived from the [OWASP LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html). OpenRouter sees a lot of injection traffic, and its list is field experience. The patterns keep OpenRouter's names (`l1/directives.py`, `PATTERNS`), so a detection can be looked up there. The KaTeX `\color{white}` fingerprint (`l1/hidden.py`) comes from OWASP alone.

Evasions are handled the way OpenRouter handles them (`l1/evasion.py`): scrambled middles (`ignroe`), one-edit typos (`1gnore`) and character spacing (`i g n o r e`) are undone, and the line is counted when the rewrite matches an exact pattern that the original did not. One rule counts without an exact pattern: two misspelled keywords on a line, at least one of them scrambled (`bpyass all safety measuers`), because nobody shuffles the middles of words by accident. A single typo is never a detection. `sytsem is down`, `systemd`, `"promt" should be "prompt"` and "the system overrides the default" all stay clean. These lines are counted as `directives_evasions_detected`, apart from exact hits.

Where Trentina departs from the source, it does so to cut false positives on ops output. `System:` as a line prefix matches only with a capital S, since `system:` opens ordinary log lines. An opening `<tool>`/`<function>` tag counts only at the start of a line, because documentation writes `<backend>__<tool>`. A keyword with a letter appended (`overrides`, `systemd`) is treated as a word rather than a typo. Measured on 31k lines of a host's journal, `podman`/`systemctl`/`ps` output and this repository's docs and source, the expansion added no detections (see #201).

OWASP's recommended "dual-LLM" architecture, where a quarantined model reads untrusted content and a privileged one acts on structured results, is what L3 already is.

**Latency:** ~55ms per 100k characters. **Cost:** Zero (no model calls). **Always runs.**

### Layer 2 — Prompt Guard 2 Classifier

Meta's Prompt Guard 2 86M model running on ONNX Runtime (CPU, no GPU required). Classifies content as `BENIGN` or `MALICIOUS` with a confidence score.

**What it catches:** Direct instruction overrides, system prompt manipulation, delimiter injection, role hijacking.

**What it misses:** Data exfiltration requests (syntactically identical to legitimate requests), social engineering (authority-based attacks that don't use injection language).

**Latency:** ~150ms (86M model, ONNX, CPU). **Cost:** Zero (runs locally). **Configurable threshold per profile.**

### Layer 3 — Quarantined LLM (Q-Agent)

A hardened Gemini Flash Lite instance that receives the **original, unmodified content** and judges it while ignoring injected instructions. It waits for L1 and L2 and is briefed with both: L1's counts, L2's label and score, and — unconditionally — the caveat that L2 misses social engineering about 40% of the time and exfiltration intent about 20%, so a low score is never evidence of safety. The Q-Agent is deliberately constrained:

- **No tools** — can't execute actions even if manipulated
- **No memory** — can't be poisoned across sessions
- **No SDK** — raw httpx calls to the Gemini REST API, no dependency surface
- **Small model** — less capable models are harder to socially engineer

**What it catches:** Social engineering, data exfiltration intent, authority-based attacks, subtle semantic manipulation — everything that requires understanding *meaning*, not just *pattern*.

**What it misses:** with the default `QUARANTINE_MODEL` (`gemini-2.5-flash-lite`), the Q-Agent's aggregate catch rate on attacks written to evade both L1 and L2 is 86% (see `benchmarks/results/`), not near-100% — and it drops to 33% on the `detector_meta` category (attacks targeting the detector itself). A stronger `QUARANTINE_MODEL` closes most of that gap; see `docs/benchmark.md` for per-model numbers before treating L3 as a reliable backstop.

**Latency:** 1-2s per turn (Gemini round-trip). **Cost:** Gemini API tokens — one call per payload, three in redact mode. **Always runs;** its absence is a gap, never a skip.

## Coverage Matrix

Benchmarked against 105 test cases across 10 attack categories (Prompt Guard 2 22M vs 86M, ONNX Runtime, CPU):

| Attack Type | L1 (Structural) | L2 (Classifier) | L3 (Q-Agent) |
|-------------|-----------------|-----------------|--------------|
| Hidden div injection | **catches** (counts; conversion removes it) | n/a | n/a |
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

### Pacing L3: the adaptive limiter

L3 is the only layer paced by someone else. Every provider call
(`quarantine/limiter.py`) waits in a FIFO queue in front of the
(provider, model) it goes to, shared by user-facing scans, the perimeter,
compression and the boot warm-up. User-facing calls are granted a slot before
warm-up work, so hundreds of tool descriptions judged at boot never make a
`tools/call` wait behind them.

The limit is found, not configured, by AIMD, the rule TCP uses:

- slow start doubles it per window until the provider first throttles;
- after that it grows by one per window of successes;
- a 429 halves it, once per congestion epoch, so a burst of 429s from requests
  that were in flight together counts once, and pauses new requests for the
  provider's `Retry-After`, or, when the provider sends none, for the
  limiter's own backoff (1s doubling to 30s, with jitter).

A throttled call is retried on the same provider after the pause, within
`TRENTINA_L3_THROTTLE_BUDGET`, and only then falls back. A 503 or a timeout is
an outage, not a capacity signal: it moves down the fallback chain at once and
leaves the limit alone.

### Boot warm-up

On a cold perimeter store, the first `tools/list` has to judge every tool
description. `gateway/warmup.py` starts that work from the FastMCP lifespan as
soon as the event loop serves, through the same single-flight build a client's
`tools/list` uses (`router.ensure_profile_build`). A client that connects
mid-warm-up joins it instead of starting its own. The warm-up logs one summary
line: its duration, profiles, tools, descriptions judged vs. cached, and each
judge's final limit and throttle count.

## Configuration

Defense settings are configured per profile:

```yaml
profiles:
  myagent:
    auth:
      bearer_token_env: TRENTINA_PROFILE_MYAGENT_TOKEN
    defense:
      enforcement: flag        # what a flag COSTS — flag | block
      l2_threshold: 0.5        # how suspicious L2 must be before it flags
```

**There are no per-layer on/off switches, and that is deliberate.** An earlier schema had
`sanitize` / `classify` / `quarantine` booleans; production ran `quarantine: false` for months
without the owner knowing, partly because none of it was wired and partly because three
unrelated words hid what they controlled. A profile behind Trentina gets all three layers, full
stop. `DefenseConfig` is `extra="forbid"`, so a config still carrying those keys does not warn —
it refuses to start.

What a profile controls is a threshold and a consequence:

- **`l2_threshold`** — how suspicious L2 must be before it FLAGS. A flag is a consequence, not
  an execution: L2 runs either way. The default is 0.5, where the model's own label turns
  MALICIOUS. Anything lower also flags content the classifier labels BENIGN, so lower it
  knowingly and measure first (#86).
- **`enforcement`** — what a flag costs. `flag` delivers the content with a
  `_trentina_warning` (the calibration mode) and `block` refuses it outright.
  `TRENTINA_ENFORCEMENT_OVERRIDE=flag` is the kill switch.

A layer that is unavailable at runtime (no ONNX model, provider down) is a degraded state that
`/health` reports and `block` refuses on. `TRENTINA_REQUIRE_L2=false` / `TRENTINA_REQUIRE_L3=false`
turn that layer's absence into a warning instead of a refusal; no setting excuses a partial read.

## Pipeline Flow

```
Stage 0  pre-processors (outside the perimeter; subtract, never absolve)
Stage 1  L1  ∥  L2          both read the payload as it arrived
Stage 2  L3 detect          waits for both; briefed with both
Stage 3  the mode decides delivery
```

The mode decides what is delivered, never which layers run (`modes.py`). The names are OpenRouter's guardrail actions, but `redact` rewrites through L3 rather than substituting spans — see [Content Tools](quarantine-tools.md#the-names-are-openrouters).

| mode | L1 | L2 | L3 detect | L3 extract | L3 verify | delivers |
|------|----|----|-----------|------------|-----------|----------|
| block | ✓ | ✓ | ✓ | — | — | nothing if any layer flagged; else the original |
| flag | ✓ | ✓ | ✓ | — | — | the original, plus the verdict |
| redact | ✓ | ✓ | ✓ | from L1's normalized copy | the extraction | a verified extraction; nothing if verify objects |

Ten rules hold on every path (#187):

1. All three layers fire. No mode, config or source property reduces the count.
2. L1 and L2 run in parallel on the arrived bytes, so their signals stay independent.
3. L3 waits for both and sees both findings.
4. The mode decides delivery, never detection.
5. Every finding reaches the agent as structure — booleans, scores, closed-enum finding types — never as text L3 wrote. A page can steer the judge into quoting it.
6. `flag` is a security-researcher grant, almost never right for an assistant, coding agent or swarm.
7. `redact` runs L3 three times: detect, extract, verify. Verify objecting refuses; there is no fourth turn.
8. Search is not special: L0's answer, titles and URLs are one document through the same path.
9. `block` and `redact` require a verdict from every layer; `flag` delivers regardless, loudly. An absent layer can be excused per layer; a partial read cannot.
10. The allowlist never skips a layer or hides a flag. It turns a block into a redact — and a redact that fails still refuses.

The gateway applies the same rule to proxied responses and tool descriptions under `defense.enforcement` (`flag` or `block`).

## Related

- [Blocklist](blocklist.md) — cumulative detection memory across sessions
- [Quarantine Tools](quarantine-tools.md) — how the defense pipeline is exposed as MCP tools
- [Per-Agent Profiles](profiles.md) — per-profile defense configuration
