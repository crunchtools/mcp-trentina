# Specification: Gateway Tool Description Compression

> **Spec ID:** 007-description-compression
> **Status:** Draft
> **Version:** 0.1.0
> **Author:** Scott McCarty
> **Date:** 2026-06-23

## Overview

MCP servers ship verbose tool descriptions that waste consumer context. This feature uses the existing Gemini Flash Lite integration to compress all tool descriptions as they pass through the gateway, caching results in SQLite so the model is only called once per unique description. Per-backend opt-in via `compress_descriptions: true` in profiles.yaml.

---

## New Tools

No new tools. Extends `quarantine_stats` output with compression metrics.

---

## Security Considerations

### Layer 1 — Token Protection
- Reuses existing `GEMINI_API_KEY` (no new credentials)
- New env var `TRENTINA_COMPRESS_MODEL` contains no secrets

### Layer 2 — Input Validation
- `compress_descriptions` field validated by Pydantic `Backend` model
- Description hashes are SHA-256 (no user input in cache keys)

### Layer 3 — API Hardening
- Gemini calls use same httpx pattern as Q-Agent (no SDK, no tools)
- Structured JSON output via `responseSchema` — no free-text parsing

### Layer 4 — Dangerous Operation Prevention
- Read-only transformation: descriptions compressed, never executed
- Original descriptions stored in SQLite alongside compressed versions for auditability

---

## Module Changes

### New Files

| File | Purpose |
|------|---------|
| `gateway/compress.py` | Core compression module: cache management, Gemini calls, lookup function, savings calculator |
| `tests/test_gateway_compress.py` | Unit tests for compression pipeline |

### Modified Files

| File | Changes |
|------|---------|
| `gateway/profile.py` | Add `compress_descriptions: bool = False` to `Backend` model |
| `gateway/router.py` | Call `compress_tools()` after `filter_tools()` in `_route_tools_list()` |
| `database.py` | Add `tool_compressions` table schema + `get_all_compressions()` / `save_compression()` helpers |
| `__init__.py` | Schedule background pre-compression task at startup |
| `tools/stats.py` | Add compression metrics to `get_trentina_stats()` output |

---

## Configuration

### profiles.yaml (per-backend)

```yaml
backends:
  gws-personal:
    url: "http://gws-personal:8011/mcp"
    compress_descriptions: true    # opt-in, default false
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TRENTINA_COMPRESS_MODEL` | `gemini-2.5-flash-lite` | Model for compression |

---

## Data Model

### SQLite Table: `tool_compressions`

```sql
CREATE TABLE IF NOT EXISTS tool_compressions (
    description_hash TEXT PRIMARY KEY,
    original_description TEXT NOT NULL,
    compressed_description TEXT NOT NULL,
    model TEXT NOT NULL,
    compressed_at TEXT NOT NULL,
    original_length INTEGER NOT NULL,
    compressed_length INTEGER NOT NULL
);
```

### Cache Strategy

- **Hot path:** module-level `dict[str, str]` mapping `sha256(original) → compressed`
- **Cold path:** SQLite table, loaded into dict at startup
- **Cache key:** `sha256(description_text)` — global, not per-profile
- **Invalidation:** hash changes when description changes (new backend version)

---

## Pipeline Integration

```
list_backend_tools()
    ↓
filter_tools()          # existing — allow/deny globs
    ↓
compress_tools()        # NEW — cache lookup, replace descriptions
    ↓
namespace rewrite       # existing — backend__toolname
    ↓
aggregate + return
```

`compress_tools()` is synchronous (dict lookup only). Model calls happen in a background task at startup via `precompress_all()`.

---

## Stats Output Extension

```json
{
  "compression": {
    "enabled": true,
    "model": "gemini-2.5-flash-lite",
    "tools_compressed": 187,
    "original_chars": 62400,
    "compressed_chars": 28080,
    "savings_percent": 55,
    "estimated_tokens_saved": 8580,
    "per_backend": {
      "gws-personal": {"tools": 45, "original": 18900, "compressed": 7560, "savings_percent": 60}
    }
  }
}
```

---

## Testing Requirements

### Unit Tests
- [ ] `compress_tools()` replaces descriptions when cache is populated
- [ ] `compress_tools()` passes through when cache is empty
- [ ] `compress_tools()` preserves `inputSchema`, `name`, `title`, `annotations` untouched
- [ ] `precompress_backend()` calls model for descriptions and stores results
- [ ] Cache persistence round-trip (write to SQLite, reload, verify)
- [ ] Model failure graceful fallback (original description preserved)
- [ ] Model returns description longer than original — discard, use original
- [ ] Batch size limiting (>20 descriptions batched correctly)

### Stats Tests
- [ ] `get_trentina_stats()` includes compression metrics when enabled
- [ ] Per-backend breakdown reflects actual compression ratios

---

## Dependencies

- Depends on: existing Gemini httpx integration (`quarantine/agent.py` pattern)
- Blocks: #22 (model provider drivers would refactor the Gemini call)

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | 2026-06-23 | Initial draft |
