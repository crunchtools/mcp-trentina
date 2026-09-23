# Web Content Quarantine Tools

Trentina's original capability: safe web fetching, file reading, and web search with prompt injection defense. These tools are exposed through the gateway as the `web` backend (`internal://web`), giving every connected agent access to the defense pipeline for untrusted content.

## Three modes, picked by the agent

Every content tool runs **all three layers**. What differs is the *disposition* — what a flagged verdict costs — and since 0.26.0 that choice is the tool's name, so the agent picks it per call.

| prefix | on a flag | what you get |
|---|---|---|
| `block_*` | refused | the bytes that arrived, or an error — never flagged content |
| `warn_*` | forwarded | **exactly** the bytes that arrived, plus `_trentina_warning` |
| `clean_*` | replaced | a Q-Agent extraction, written by a quarantined LLM that read the content |

Four families: `fetch`, `read`, `content`, `search`. Twelve tools.

**`warn_*` is new.** Before 0.26.0 an agent could be refused or handed an LLM rewrite, and nothing in between — so the one posture with the best argument behind it was unreachable from a tool call. A warning that lands in context *ahead of* the payload is the difference between an agent reading hostile content credulously and reading it on guard. It is advisory, not a wall: a convincing enough injection can still talk an agent past its own warning, which is why it is a complement to L1/L2/L3 and not a replacement.

`warn_*` is also the only mode that satisfies the owner's rule in both directions — *what the agent receives is byte-identical to what entered the perimeter, or nothing at all* — even when the verdict is bad.

Which modes a given profile is offered is the existing `tools_allow` filter. No new permission machinery.

### Choosing

- Acting unsupervised on what you read → `block_*`.
- Need the real bytes and can weigh a caution — a CVE advisory, a log excerpt, anything that legitimately discusses attacks in the words attacks use → `warn_*`.
- Want the information and not the page → `clean_*`.

### Removed spellings

`safe_*` and `quarantine_*` were removed in **0.29.0**, having been deprecated since 0.26.0. There is no alias; a call to one now fails with "unknown tool".

| removed | use |
|---|---|
| `block_fetch` / `block_read` / `block_content` / `block_search` | `block_*` |
| `clean_fetch` / `clean_read` / `clean_content` / `clean_search` | `clean_*` |

The old names described a *trust model* ("safe", "quarantine") while actually encoding a disposition, and both families always ran all three layers — so the "Layers" column this table used to carry was decoration. The new names say what the mode does.

Note that `quarantine_scan`, `deep_quarantine_scan` and `quarantine_stats` are NOT affected: they are diagnostics, they carry no mode prefix because they report rather than deliver, and they keep their names.

## What every response carries

Three independent facts, never collapsed into one grade. There is no trust
level, because content that crossed the perimeter is untrusted — permanently.
The layers are *detectors*, and a detector finding nothing has not made
anything safe; it has failed to find something.

```json
"scan": {
  "layers":      {"l1": "complete", "l2": "complete", "l3": "unavailable"},
  "disposition": "annotated",
  "origin":      {"kind": "url", "ref": "https://example.com", "allowlisted": false}
}
```

**`layers`** — what ran, and whether it finished. `complete`, `partial` (L2 hit
its token cap), `unavailable` (no ONNX model, no API key, provider error), or
`not_applicable` (nothing to judge). *A scan that did not happen must never
read like a scan that found nothing*, which is why `unavailable` and
`complete` are different words.

**`disposition`** — what was done. `delivered` (the bytes that arrived,
nothing attached), `annotated` (those bytes plus `_trentina_warning`),
`extracted` (a Q-Agent extraction *instead of* the original — `extracted_by`
names the model), `refused` (nothing delivered; the tool raised), `reported`
(a diagnostic returned findings about a payload without delivering it).

**`origin`** — where it came from, and whether an operator has allowlisted
that source. Allowlisting **suppresses flags; it does not skip layers**: a
trusted source still runs L1, L2 and L3, and `allowlisted: true` is what
explains why a detection did not become a refusal.

What was *found* is not here. That is `_trentina_warning`'s job, and two
sources for one fact is two answers that can disagree.

> Note the one case worth reading carefully: `clean_*` against an allowlisted
> source skips the Q-Agent entirely and hands back the original text. That is
> `disposition: delivered`, not `extracted` — you asked for an extraction and
> did not get one.

## Diagnostic tools

These report rather than deliver, and take no mode prefix:

| Tool | Behavior |
|------|----------|
| `quarantine_scan` | Threat assessment only — no content returned |
| `deep_quarantine_scan` | Q-Agent sees raw content for better detection |
| `scan_content` | Threat assessment on inline text |
| `deep_scan_content` | Inline content, raw to L2/L3 |
| `quarantine_scan_dir` | Scan a directory for Python module shadowing |
| `quarantine_stats` | Configuration, blocklist, and audit summary |

## Search Tools

The search tools add a Layer 0 step — Gemini grounding with `google_search` — before the content enters the defense pipeline:

```
L0 (Gemini grounding) → resolve redirects → L1 builds `l2_input` → L2 classify → L3
```

`block_search` and `warn_search` return grounded prose + source URLs; they differ only in whether a flagged answer is refused or delivered with the reason attached. `clean_search` adds structured extraction with per-source summaries and relevance scores.

## Content Tools

The content tools (`block_content`, `warn_content`, `clean_content`, `deep_scan_content`) operate on inline text rather than fetching from a URL or file. These are useful when content arrives through a channel that isn't a URL — for example, inspecting the body of an MCP tool response, a clipboard paste, or text extracted from another system.

## Deep Scan Tools

The deep scan variants (`deep_quarantine_scan`, `deep_scan_content`) send the *raw* content to L3 for analysis. L1 still runs for stats reporting, but L3 receives the original content for full semantic analysis. This provides better detection at the cost of higher L3 compromise risk. Use these for diagnostic deep-dives on suspicious content.

## Trust Domains

Trentina supports a trust allowlist for known-safe domains. Trusted domains skip the Q-Agent on `block_fetch` and `warn_fetch` (L1 only, no model calls). Untrusted domains get the full pipeline:

```json
{
  "trusted_domains": [
    "docs.python.org",
    "developer.mozilla.org",
    "man7.org"
  ]
}
```

Configure via `QUARANTINE_TRUST_CONFIG` environment variable pointing to a JSON file.

## Gateway Integration

Through the gateway, quarantine tools appear as `web__block_fetch_tool`, `web__clean_search_tool`, etc. They're just another backend — the agent calls them the same way it calls any other tool, and the gateway handles namespacing and audit logging.

## Related

- [Defense Pipeline](defense-pipeline.md) — the L1/L2/L3 layers these tools use
- [Blocklist](blocklist.md) — how detected sources are remembered
- [MCP Gateway](gateway.md) — how quarantine tools are exposed through the gateway
