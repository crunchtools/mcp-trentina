# Implementation Plan: Automatic Provider Fallback Chain

> **Spec ID:** 012-provider-fallback-chain
> **Status:** Planning
> **Last Updated:** 2026-07-22

## Summary

Add a `provider_fallback` config field, a `_call_with_fallback()` wrapper in `agent.py`, and a `get_fallback_providers()` helper in `providers/__init__.py`. The wrapper iterates the chain on retryable errors; non-retryable errors short-circuit. `search_grounded()` is excluded.

---

## Architecture

### Fallback Flow

```
_call_gemini() called with provider_name=None (primary)
    │
    ▼
_call_with_fallback([primary] + fallback_chain)
    │
    ├─ attempt provider[0] (primary)
    │   ├─ success → return result
    │   ├─ retryable error → log warning, try provider[1]
    │   └─ non-retryable → raise immediately
    │
    ├─ attempt provider[1] (first fallback)
    │   ├─ success → return result
    │   ├─ retryable → log warning, try provider[2]
    │   └─ non-retryable → raise immediately
    │
    └─ all exhausted → raise QuarantineAgentError (caught by quarantine_extract / quarantine_detect)
```

### Data Flow

1. `config.py` parses `TRENTINA_PROVIDER_FALLBACK` into `config.provider_fallback: list[str]`
2. `get_fallback_providers()` in `providers/__init__.py` resolves each name to `(name, api_key)`, skipping providers with no key in current profile
3. `_call_with_fallback()` in `agent.py` loops: calls `_call_gemini(provider_name=name, api_key=key)` per provider, catches retryable exceptions, moves to next
4. `quarantine_extract()` and `quarantine_detect()` catch the final `QuarantineAgentError` as before

---

## Implementation Steps

### Phase 1: Config

- [ ] Add `provider_fallback: list[str]` to `Config.__init__()` — parse `TRENTINA_PROVIDER_FALLBACK` env var as comma-split, strip whitespace, validate each against `SUPPORTED_PROVIDERS`, raise `ConfigError` on unknown names
- [ ] Add `DEFAULT_PROVIDER_FALLBACK: list[str] = []` constant

### Phase 2: Provider Helper

- [ ] Add `get_fallback_providers(profile=None)` to `quarantine/providers/__init__.py`
  - Reads `config.provider_fallback`
  - For each provider name, resolves the API key (gateway mode: from profile; standalone: from config)
  - Skips providers with no key (warns via logging)
  - Returns `list[tuple[str, SecretStr | None]]` — `(provider_name, api_key_or_none)`

### Phase 3: Fallback Wrapper

- [ ] Add `_is_retryable(exc: Exception) -> bool` in `agent.py`
  - Returns True for `httpx.TimeoutException`, `httpx.ConnectError`
  - Returns True for `QuarantineAgentError` wrapping HTTP 429 or 503 (need to preserve status code in error or check message)
  - Returns False for everything else

- [ ] Add `_call_with_fallback(content, system_prompt, response_schema, user_prompt)` in `agent.py`
  - Builds provider chain: `[(primary_name, primary_key)] + get_fallback_providers()`
  - Loops, calling `_call_gemini(provider_name=name, api_key=key, ...)` per provider
  - On retryable error: log `WARNING provider {name} failed ({err}), trying {next_name}`, continue
  - On non-retryable error: re-raise immediately
  - On exhaustion: raise `QuarantineAgentError("all providers exhausted: {names}")`

- [ ] Replace direct `_call_gemini()` calls in `quarantine_extract()` and `quarantine_detect()` with `_call_with_fallback()`

### Phase 4: HTTP Status Code Preservation

To distinguish 429/503 from 400/401/403 in `_is_retryable()`, the provider implementations need to surface the status code. Options:

**Option A (preferred):** Add `status_code: int | None = None` field to `QuarantineAgentError` and have each provider driver set it when raising. Requires modifying all four provider drivers but keeps the error hierarchy clean.

**Option B:** Parse the status code from the error message string. Fragile — avoid.

Use Option A. Add `status_code` to `QuarantineAgentError.__init__()` and update all four drivers (Gemini, OpenAI, Anthropic, Ollama) to pass it.

### Phase 5: Tests

- [ ] Create `tests/test_provider_fallback.py`
- [ ] Mock `httpx.AsyncClient` in relevant provider tests to simulate 429, 503, timeout, connect error
- [ ] Test all scenarios from spec Testing Requirements section
- [ ] Add config parsing tests (valid chain, invalid provider, empty)

### Phase 6: Quality Gates

- [ ] `uv run ruff check src tests`
- [ ] `uv run mypy src`
- [ ] `uv run pytest -v`
- [ ] `podman run --rm -v .:/repo:Z quay.io/crunchtools/gourmand:latest --full /repo`
- [ ] `podman build -f Containerfile .`

---

## File Changes

### New Files

| File | Purpose |
|------|---------|
| `tests/test_provider_fallback.py` | Fallback chain unit tests |

### Modified Files

| File | Changes |
|------|---------|
| `config.py` | Add `provider_fallback` field and `DEFAULT_PROVIDER_FALLBACK` constant |
| `errors.py` | Add `status_code: int \| None` field to `QuarantineAgentError` |
| `quarantine/providers/__init__.py` | Add `get_fallback_providers()` helper |
| `quarantine/providers/gemini.py` | Pass `status_code` when raising `QuarantineAgentError` |
| `quarantine/providers/openai.py` | Pass `status_code` when raising `QuarantineAgentError` |
| `quarantine/providers/anthropic.py` | Pass `status_code` when raising `QuarantineAgentError` |
| `quarantine/providers/ollama.py` | Pass `status_code` when raising `QuarantineAgentError` |
| `quarantine/agent.py` | Add `_is_retryable()`, `_call_with_fallback()`, update callers |

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Status code not preserved in error | Med | Option A: add `status_code` field to `QuarantineAgentError`; update all drivers |
| Fallback leaks canary from failed attempt | Low | Canary is re-generated per `_call_gemini()` call; failed-attempt canary is never validated |
| Gateway mode: profile has partial key set | Med | `get_fallback_providers()` skips providers with no key and logs a warning |
| Infinite retry if error classification wrong | Low | Hard cap: at most `len(chain)` iterations; non-retryable always short-circuits |

---

## Changelog

| Date | Changes |
|------|---------|
| 2026-07-22 | Initial plan |
