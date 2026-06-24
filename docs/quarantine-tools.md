# Web Content Quarantine Tools

Trentina's original capability: safe web fetching, file reading, and web search with prompt injection defense. These tools are exposed through the gateway as the `web` backend (`internal://web`), giving every connected agent access to the defense pipeline for untrusted content.

## Tools

| Tool | Layers | Behavior on Detection |
|------|--------|-----------------------|
| `safe_fetch` | L1+L2 | **Fails** — returns error, blocks content |
| `safe_read` | L1+L2 | **Fails** — returns error, blocks content |
| `safe_search` | L0+L1+L2 | **Fails** — returns error if search results contain injection |
| `safe_content` | L1+L2+L3 | **Fails** — sanitize inline content, reject on injection |
| `quarantine_fetch` | L1+L2+L3 | **Warns** — extracts content through Q-Agent, adds warning |
| `quarantine_read` | L1+L2+L3 | **Warns** — extracts content through Q-Agent, adds warning |
| `quarantine_search` | L0+L1+L2+L3 | **Warns** — search with full pipeline, structured extraction |
| `quarantine_content` | L1+L2+L3 | **Warns** — sanitize inline content, extract via Q-Agent |
| `quarantine_scan` | L1+L2+L3 | **Scan only** — returns threat assessment, no content |
| `deep_quarantine_scan` | L1+L2+L3 | **Deep scan** — Q-Agent sees raw content for better detection |
| `deep_scan_content` | L1+L2+L3 | **Deep scan** — inline content, raw to L2/L3 |
| `quarantine_stats` | — | Configuration, blocklist, and audit summary |

## Safe vs. Quarantine

The two families serve different trust models:

**Safe tools** are fail-closed. If any defense layer detects injection, the content is blocked and an error is returned. The agent never sees the content. Use these when you'd rather miss the content than risk an injection.

**Quarantine tools** are warn-and-proceed. Detected injection triggers a warning in the response metadata, but the content is still extracted through the Q-Agent and returned. Use these when you need the content even if it might be hostile — the Q-Agent extracts useful information while the injected instructions stay quarantined.

## Search Tools

The search tools add a Layer 0 step — Gemini grounding with `google_search` — before the content enters the defense pipeline:

```
L0 (Gemini grounding) → resolve redirects → L1 sanitize → L2 classify → L3 Q-Agent
```

`safe_search` returns sanitized prose + source URLs. `quarantine_search` adds structured extraction with per-source summaries and relevance scores.

## Content Tools

The content tools (`safe_content`, `quarantine_content`, `deep_scan_content`) operate on inline text rather than fetching from a URL or file. These are useful when content arrives through a channel that isn't a URL — for example, inspecting the body of an MCP tool response, a clipboard paste, or text extracted from another system.

## Deep Scan Tools

The deep scan variants (`deep_quarantine_scan`, `deep_scan_content`) send the *unsanitized* content to the Q-Agent for analysis. L1 still runs for stats reporting, but the Q-Agent receives the original content for full semantic analysis. This provides better detection at the cost of higher Q-Agent compromise risk. Use these for diagnostic deep-dives on suspicious content.

## Trust Domains

Trentina supports a trust allowlist for known-safe domains. Trusted domains skip the Q-Agent on `safe_fetch` (L1 only, no model calls). Untrusted domains get the full pipeline:

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
