# Tool Description Compression

Trentina compresses MCP tool descriptions as they pass through the gateway, reducing context token usage by 70-77% without affecting tool usability. Compressed descriptions are cached in SQLite so the LLM is only called once per unique description — after the first run, it's a local lookup.

## Why This Matters

MCP servers ship verbose tool descriptions. A typical Google Workspace backend has 130 tools, each with multi-paragraph descriptions, inline examples, and detailed parameter documentation. Across 20+ backends, this can consume 15-25K tokens of context on tool definitions alone — before the agent does any actual work.

Agents don't need verbose descriptions to use tools correctly. Tool names, parameter names, and type schemas carry enough signal for capable models. The prose is redundant.

## How It Works

### Compression Pipeline

1. **Lazy trigger**: On the first `tools/list` request, Trentina checks which backends have `compress_descriptions: true` enabled
2. **Cache check**: Each tool description is hashed (SHA-256). If the hash exists in the SQLite cache, the compressed version is returned immediately — zero model calls
3. **Batch compression**: Cache misses are batched (up to 20 descriptions per API call) and sent to Gemini Flash Lite with a structured output schema that forces concise summaries
4. **Cache storage**: Compressed descriptions are stored in SQLite keyed by description hash. Same description from any backend/profile gets one cache entry
5. **Passthrough on failure**: If the model is unavailable, the original description passes through unchanged

### Cache Architecture

```
tools/list request
    ↓
For each tool:
    hash = sha256(description)
    if hash in memory_cache:
        use compressed description
    elif hash in sqlite_cache:
        load to memory_cache, use compressed
    else:
        queue for batch compression
```

The in-memory cache makes the hot path a dict lookup — no model calls, no database queries during normal operation.

### Configuration

```yaml
backends:
  gws-personal:
    url: "http://gws-personal:8011/mcp"
    compress_descriptions: true   # enable compression for this backend
  slack:
    url: "http://mcp-slack:8005/mcp"
    # compress_descriptions: false  (default — leave verbose)
```

The compression model can be configured via environment variable:

```bash
TRENTINA_COMPRESS_MODEL=gemini-2.5-flash-lite  # default
```

## Real-World Results

From the CrunchTools deployment (154 tools across 21 backends):

| Metric | Value |
|--------|-------|
| Tools compressed | 154 |
| Original characters | 62,014 |
| Compressed characters | 17,228 |
| **Savings** | **72%** |
| Estimated tokens saved | ~11,196 |

### Per-Backend Savings

Some backends benefit more than others — servers with verbose, example-heavy descriptions see the largest reductions:

| Backend | Reduction |
|---------|-----------|
| Memory | 91% |
| Jira | 87% |
| Google Workspace | ~75% |
| CrunchTools servers | ~60% |

### Total Context Cost

With both tool filtering and compression applied, the entire 154-tool surface fits in approximately 4,300 tokens — roughly the size of a short blog post. Without compression, the same tools would consume ~15,500 tokens.

## What Gets Compressed

- **Tool descriptions** — the `description` field in the tool definition
- **Parameter descriptions** — the `description` fields inside `inputSchema.properties`

## What Stays Unchanged

- **Tool names** — always preserved exactly
- **Parameter names** — always preserved exactly
- **Parameter types** — `string`, `integer`, `boolean`, etc.
- **Required fields** — the `required` array
- **JSON schema structure** — `oneOf`, `anyOf`, `enum`, etc.

The structural schema is what agents actually need to construct valid tool calls. The prose descriptions are supplementary context that compression can safely reduce.

## Monitoring

The `quarantine_stats` tool includes compression metrics:

```json
{
  "compression": {
    "tools_compressed": 154,
    "original_chars": 62014,
    "compressed_chars": 17228,
    "savings_percent": 72,
    "estimated_tokens_saved": 11196
  }
}
```

## Related

- [Tool Filtering](tool-filtering.md) — the first layer of context reduction (removing tools entirely)
- [MCP Gateway](gateway.md) — where compression sits in the gateway pipeline
- [Per-Agent Profiles](profiles.md) — enabling compression per-backend
