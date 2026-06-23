# Implementation Plan: Gateway Tool Description Compression

> **Spec ID:** 007-description-compression
> **Status:** Planning
> **Last Updated:** 2026-06-23

## Summary

Add LLM-powered tool description compression to the gateway. Descriptions are pre-compressed at startup using Gemini Flash Lite (same httpx pattern as Q-Agent), cached in SQLite, and looked up synchronously during `tools/list`. Per-backend opt-in via profiles.yaml.

---

## Architecture

### Data Flow

```
Gateway Startup
    │
    ▼
precompress_all(profiles)
    │ iterates compression-enabled backends
    ▼
list_backend_tools(backend)
    │ fetches raw tool list from backend
    ▼
_call_compress_model(descriptions[])
    │ batched Gemini call (up to 20 per request)
    │ raw httpx, structured JSON output
    ▼
save_compression(hash, original, compressed)
    │ writes to SQLite + updates in-memory dict
    ▼
_cache: dict[str, str]  ← ready for request-time lookup
```

```
Request-time tools/list
    │
    ▼
filter_tools()           # existing
    ▼
compress_tools(filtered) # NEW — dict lookup per tool, O(1)
    ▼
namespace rewrite        # existing
```

---

## Implementation Steps

### Phase 1: Database Schema

- [ ] Add `tool_compressions` table to `SCHEMA` in `database.py`
- [ ] Add `get_all_compressions() -> dict[str, str]` helper
- [ ] Add `save_compression(hash, original, compressed, model)` helper

### Phase 2: Compression Module

- [ ] Create `gateway/compress.py` with:
  - Module-level `_cache: dict[str, str]`
  - `load_compression_cache()` — populate from SQLite
  - `compress_tools(tools: list[dict]) -> list[dict]` — sync lookup
  - `async precompress_backend(backend_name, backend) -> int`
  - `async precompress_all(profiles) -> dict[str, int]`
  - `async _call_compress_model(descriptions: list[tuple[str, str]]) -> list[tuple[str, str]]`
  - `get_compression_stats() -> dict` — savings calculator

### Phase 3: Profile Model

- [ ] Add `compress_descriptions: bool = False` to `Backend` in `profile.py`

### Phase 4: Router Integration

- [ ] Import `compress_tools` in `router.py`
- [ ] Call after `filter_tools()`, before namespace loop in `_route_tools_list()`

### Phase 5: Startup Integration

- [ ] In `__init__.py` `_run_with_gateway()`: call `load_compression_cache()` then schedule `precompress_all()` as background task

### Phase 6: Stats Extension

- [ ] Import `get_compression_stats` in `tools/stats.py`
- [ ] Add compression metrics to `get_trentina_stats()` output

### Phase 7: Tests

- [ ] Create `tests/test_gateway_compress.py`
- [ ] Test cache lookup (hit/miss/passthrough)
- [ ] Test description preservation (inputSchema untouched)
- [ ] Test SQLite round-trip
- [ ] Test model failure fallback
- [ ] Test batch splitting
- [ ] Test stats output

### Phase 8: Quality Gates

- [ ] `uv run ruff check src tests`
- [ ] `uv run mypy src`
- [ ] `uv run pytest -v`
- [ ] `podman build -f Containerfile .`

---

## File Changes

### New Files

| File | Purpose |
|------|---------|
| `gateway/compress.py` | Core compression: cache, model calls, lookup, stats |
| `tests/test_gateway_compress.py` | Unit tests |

### Modified Files

| File | Changes |
|------|---------|
| `gateway/profile.py` | Add `compress_descriptions` field to `Backend` |
| `gateway/router.py` | Call `compress_tools()` in `_route_tools_list()` |
| `database.py` | Add `tool_compressions` table + helpers |
| `__init__.py` | Schedule pre-compression at startup |
| `tools/stats.py` | Add compression metrics |

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Gemini unavailable at startup | Med | Cache passthrough — original descriptions used. Log warning. |
| Model returns longer text | Low | Discard, use original. Compare lengths before storing. |
| Batch mismatch (fewer results) | Low | Match by hash ID. Missing = passthrough. |
| tools/list latency increase | High | Compression is sync dict lookup only. No model calls in hot path. |
| Stale cache after backend update | Low | Hash changes → new compression on next startup cycle. |

---

## Changelog

| Date | Changes |
|------|---------|
| 2026-06-23 | Initial plan |
