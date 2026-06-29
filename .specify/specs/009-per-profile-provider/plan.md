# Implementation Plan: Per-Profile LLM Provider Selection

> **Spec ID:** 009-per-profile-provider
> **Status:** Planning
> **Last Updated:** 2026-06-29

## Summary

Thread an optional provider name from `DefenseConfig` through the provider resolution layer. Change `get_provider()` from a global singleton to a per-name cache so multiple providers can coexist.

---

## Architecture

### Provider Resolution Flow

```
Profile (profiles.yaml)
    │
    │ defense.provider = "anthropic" (or None)
    │
    ▼
get_provider(provider_name=...)     ← NEW optional param
    │
    │ provider_name set? → resolve it
    │ provider_name None? → fall back to TRENTINA_MODEL_PROVIDER
    │
    ▼
_provider_cache["anthropic"]        ← NEW per-name cache
    │
    ▼
AnthropicProvider instance
```

### Call Sites

1. **Compression** (`compress.py`): `_call_compress_model()` calls `get_provider()` — needs provider name from the backend's parent profile
2. **Q-Agent** (`agent.py`): `_call_gemini()` calls `get_provider()` — needs provider name for Phase 2 defense pipeline integration
3. **Standalone tools** (`tools/*.py`): use global default (no profile context)

---

## Implementation Steps

### Phase 1: DefenseConfig Field

- [ ] Add `provider: str | None = Field(default=None)` to `DefenseConfig`
- [ ] Add validator: if set, must be in `SUPPORTED_PROVIDERS`

### Phase 2: Per-Name Provider Cache

- [ ] Change `_cached_provider` to `_provider_cache: dict[str, Provider]`
- [ ] Make `get_provider()` accept optional `provider_name: str | None`
- [ ] When `provider_name` is None, read from global config (current behavior)
- [ ] Cache keyed on resolved provider name
- [ ] Update `reset_provider()` to clear the dict

### Phase 3: Thread Through Compression

- [ ] `_call_compress_model()` accepts optional `provider_name`
- [ ] `_precompress_backend()` passes provider name from profile
- [ ] `precompress_all()` resolves provider name per profile

### Phase 4: Thread Through Q-Agent

- [ ] `_call_gemini()` accepts optional `provider_name`
- [ ] `quarantine_extract()` accepts optional `provider_name`
- [ ] `quarantine_detect()` accepts optional `provider_name`

### Phase 5: Tests

- [ ] Profile model validation tests
- [ ] Provider cache per-name tests
- [ ] Integration tests (compression + Q-Agent with override)

### Phase 6: Quality Gates

- [ ] `uv run ruff check src tests`
- [ ] `uv run mypy src`
- [ ] `uv run pytest -v`
- [ ] `gourmand --full .`

---

## File Changes

### Modified Files

| File | Changes |
|------|---------|
| `gateway/profile.py` | Add `provider` field + validator to `DefenseConfig` |
| `quarantine/providers/__init__.py` | Per-name cache, optional param on `get_provider()` |
| `gateway/compress.py` | Thread provider name through compression pipeline |
| `quarantine/agent.py` | Accept provider override in `_call_gemini()` and public functions |
| `tests/test_gateway_profile.py` | DefenseConfig provider validation tests |
| `tests/test_providers.py` | Per-name cache and override tests |
| `tests/test_gateway_compress.py` | Compression with provider override |
| `tests/test_qagent.py` | Q-Agent with provider override |

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Breaking singleton cache | High | Per-name dict; None key = global default |
| Test isolation | Med | `reset_provider()` clears entire dict |
| Missing API key for profile provider | Med | Existing error path in `get_provider()` already handles this |

---

## Changelog

| Date | Changes |
|------|---------|
| 2026-06-29 | Initial plan |
