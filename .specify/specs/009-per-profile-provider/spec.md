# Specification: Per-Profile LLM Provider Selection

> **Spec ID:** 009-per-profile-provider
> **Status:** Draft
> **Version:** 0.1.0
> **Author:** Scott McCarty
> **Date:** 2026-06-29

## Overview

Add an optional `provider` field to `DefenseConfig` so each gateway profile can use a different LLM provider for L3 Q-Agent operations and tool description compression. Profiles without a provider set fall back to `TRENTINA_MODEL_PROVIDER`. This enables cost/quality tradeoffs per consumer — e.g., josui uses anthropic for better detection, kagetora uses gemini for cheapest cost.

---

## New Tools

None. This is an internal configuration enhancement.

---

## Security Considerations

### Layer 1 — Token Protection
- No new tokens. All provider API keys remain env-var sourced.
- Per-profile provider selection uses the same key resolution already in `config.py`.

### Layer 2 — Input Validation
- New `provider` field on `DefenseConfig` is validated via Pydantic with `extra="forbid"`.
- Provider name validated against `SUPPORTED_PROVIDERS` constant.

### Layer 3 — API Hardening
- No change to Q-Agent quarantine. Provider drivers already enforce TLS, timeouts, no tools.

### Layer 4 — Dangerous Operation Prevention
- No new shell, eval, or file-write paths.

---

## Module Changes

### New Files

None.

### Modified Files

| File | Changes |
|------|---------|
| `gateway/profile.py` | Add `provider: str \| None` to `DefenseConfig` with validator |
| `quarantine/providers/__init__.py` | Make `get_provider()` accept optional provider name; cache per-name |
| `gateway/compress.py` | Thread profile provider through compression calls |
| `quarantine/agent.py` | Accept optional provider override in `_call_gemini()`, `quarantine_extract()`, `quarantine_detect()` |

---

## Testing Requirements

### Unit Tests
- [ ] `DefenseConfig` accepts valid `provider` field (gemini, openai, anthropic, ollama)
- [ ] `DefenseConfig` rejects invalid provider names
- [ ] `DefenseConfig` defaults to `None` when omitted
- [ ] `get_provider("anthropic")` returns an Anthropic provider (not the global default)
- [ ] `get_provider()` with no args returns the global default (backwards compatible)
- [ ] Per-name caching: same provider name returns same instance

### Integration Tests
- [ ] Compression uses profile provider when set
- [ ] Q-Agent uses profile provider when set
- [ ] Profile without provider falls through to global default

### Tool Count Update
- [ ] No change (no new tools)

---

## Dependencies

- Depends on: PR #40 (pluggable provider drivers) — merged
- Blocks: #42 (automatic provider fallback chain), #43 (provider benchmark harness)

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | 2026-06-29 | Initial draft |
