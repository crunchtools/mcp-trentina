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

### Deprecated spellings

`safe_*` and `quarantine_*` still work and are removed in **0.28.0**.

| old | new |
|---|---|
| `safe_fetch` / `safe_read` / `safe_content` / `safe_search` | `block_*` |
| `quarantine_fetch` / `quarantine_read` / `quarantine_content` / `quarantine_search` | `clean_*` |

The old names described a *trust model* ("safe", "quarantine") while actually encoding a disposition, and both families always ran all three layers — so the "Layers" column this table used to carry was decoration. The new names say what the mode does.

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
L0 (Gemini grounding) → resolve redirects → L1 scan view → L2 classify → L3 Q-Agent
```

`block_search` and `warn_search` return grounded prose + source URLs; they differ only in whether a flagged answer is refused or delivered with the reason attached. `clean_search` adds structured extraction with per-source summaries and relevance scores.

## Content Tools

The content tools (`block_content`, `warn_content`, `clean_content`, `deep_scan_content`) operate on inline text rather than fetching from a URL or file. These are useful when content arrives through a channel that isn't a URL — for example, inspecting the body of an MCP tool response, a clipboard paste, or text extracted from another system.

## Deep Scan Tools

The deep scan variants (`deep_quarantine_scan`, `deep_scan_content`) send the *unsanitized* content to the Q-Agent for analysis. L1 still runs for stats reporting, but the Q-Agent receives the original content for full semantic analysis. This provides better detection at the cost of higher Q-Agent compromise risk. Use these for diagnostic deep-dives on suspicious content.

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

Through the gateway, quarantine tools appear as `web__safe_fetch_tool`, `web__quarantine_search_tool`, etc. They're just another backend — the agent calls them the same way it calls any other tool, and the gateway handles namespacing and audit logging.

## Related

- [Defense Pipeline](defense-pipeline.md) — the L1/L2/L3 layers these tools use
- [Blocklist](blocklist.md) — how detected sources are remembered
- [MCP Gateway](gateway.md) — how quarantine tools are exposed through the gateway
