# Specification: Automatic Provider Fallback Chain

> **Spec ID:** 012-provider-fallback-chain
> **Status:** Draft
> **Version:** 0.1.0
> **Author:** Scott McCarty
> **Date:** 2026-07-22

## Overview

When the configured primary LLM provider fails with a retryable error (HTTP 429, 503, network timeout, or connection error), Trentina tries the next provider in a configured fallback chain before falling back to L1-only mode. Non-retryable errors (HTTP 400 schema errors, 401/403 auth errors) short-circuit immediately — they indicate a misconfiguration that retrying won't fix. This is separate from the gateway circuit breaker (#37), which handles backend tool-list failures at the proxy layer.

---

## New Tools

None — this is an internal resilience feature, not a new MCP tool.

---

## Security Considerations

### Layer 1 — Token Protection
- Fallback providers use their own API keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`) stored as plain strings in `Config`. No new secret handling added; existing providers already use these fields.
- Gateway mode: per-profile API keys still take precedence over global config keys for non-Ollama providers. The fallback chain respects profile context — if a profile has no key for a fallback provider, that provider is skipped.

### Layer 2 — Input Validation
- `TRENTINA_PROVIDER_FALLBACK` is parsed as a comma-separated list and each element is validated against `SUPPORTED_PROVIDERS` at config load time. Invalid provider names raise `ConfigError` early.
- An empty fallback list means no chain — identical to current behavior.

### Layer 3 — API Hardening
- No new endpoints. The fallback chain calls existing `provider.generate()` implementations.
- Canary tokens are re-generated per attempt so each provider's response is independently checked. A canary leak on a failed attempt is logged but does not block the retry.

### Layer 4 — Dangerous Operation Prevention
- No file, shell, or eval access.
- The fallback loop has a hard cap: at most `len(chain)` iterations. No unbounded retry.

---

## Module Changes

### New Files

None.

### Modified Files

| File | Changes |
|------|---------|
| `config.py` | Add `provider_fallback: list[str]` field parsed from `TRENTINA_PROVIDER_FALLBACK` env var |
| `quarantine/agent.py` | Add `_call_with_fallback()` wrapper around `_call_gemini()` that iterates the chain on retryable errors |
| `quarantine/providers/__init__.py` | Add `get_fallback_providers()` helper that resolves the chain to a list of `(provider_name, api_key)` tuples, skipping entries without a key in the current profile context |

### Retryable vs Non-Retryable Errors

| Error | Retryable | Reason |
|-------|-----------|--------|
| HTTP 429 (rate limit) | Yes | Transient capacity issue |
| HTTP 503 (service unavailable) | Yes | Transient provider outage |
| `httpx.TimeoutException` | Yes | Network timeout |
| `httpx.ConnectError` | Yes | Network unreachable |
| HTTP 400 (bad request) | No | Schema/request error — won't improve |
| HTTP 401 (unauthorized) | No | Auth misconfiguration |
| HTTP 403 (forbidden) | No | Auth misconfiguration |
| `json.JSONDecodeError` | No | Malformed response — provider-specific bug |

---

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `TRENTINA_MODEL_PROVIDER` | `gemini` | Primary provider |
| `TRENTINA_PROVIDER_FALLBACK` | `""` (empty = disabled) | Comma-separated fallback chain, e.g. `openai,anthropic` |

Example: primary=gemini, fallback to openai then anthropic:
```
TRENTINA_MODEL_PROVIDER=gemini
TRENTINA_PROVIDER_FALLBACK=openai,anthropic
```

Sequence on retryable failure: gemini → openai → anthropic → L1-only (or raise if `QUARANTINE_FALLBACK=fail`).

### `search_grounded()` exclusion

`search_grounded()` in `agent.py` uses Gemini directly via raw httpx with `config.api_key` and the `google_search` grounding tool. It does **not** go through the provider abstraction and will **not** participate in the fallback chain. If it fails, it raises `QuarantineAgentError` as before.

---

## Testing Requirements

### Unit Tests (`tests/test_quarantine_agent.py` or new `tests/test_provider_fallback.py`)

- [ ] Primary provider succeeds — no fallback attempted
- [ ] Primary returns HTTP 429 → fallback provider called
- [ ] Primary returns HTTP 503 → fallback provider called
- [ ] Primary raises `httpx.TimeoutException` → fallback provider called
- [ ] Primary raises `httpx.ConnectError` → fallback provider called
- [ ] All providers in chain fail → L1-only fallback (if `QUARANTINE_FALLBACK=layer1`)
- [ ] All providers in chain fail → raises `QuarantineAgentError` (if `QUARANTINE_FALLBACK=fail`)
- [ ] Primary returns HTTP 400 → no fallback, immediate fail
- [ ] Primary returns HTTP 401 → no fallback, immediate fail
- [ ] Empty fallback chain → behaves identically to current code
- [ ] Gateway mode: profile with no key for fallback provider skips that provider

### Config Tests

- [ ] `TRENTINA_PROVIDER_FALLBACK=openai,anthropic` parses to `["openai", "anthropic"]`
- [ ] `TRENTINA_PROVIDER_FALLBACK=invalid` raises `ConfigError`
- [ ] `TRENTINA_PROVIDER_FALLBACK=""` parses to `[]`

---

## Dependencies

- Depends on: PR #40 (pluggable provider drivers) — merged 2026-06-29
- Blocks: None

---

## Open Questions

None — requirements are clear from issue #42.

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | 2026-07-22 | Initial draft |
