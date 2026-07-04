# Implementation Plan: Per-Profile LLM Proxy Keys

> **Spec ID:** 011-per-profile-llm-key
> **Status:** Complete
> **Last Updated:** 2026-07-03

## Summary

Authenticate `/llm/{provider}/{path}` against the caller's existing gateway
bearer token, resolve the profile, and inject that profile's provider key
(required, no global fallback). Reuses the per-profile override shape from
009-per-profile-provider.

---

## Architecture

### Request Flow

```
Agent (Kagetora/Takeda)
    │  POST /llm/gemini/v1beta/models/...:generateContent
    │  Authorization: Bearer <profile gateway token>
    ▼
llm_proxy._proxy_llm
    │ 1. provider = providers[{provider}]         -> 404 if unknown
    │ 2. profile = resolve_profile_by_token(auth) -> 401 if none
    │ 3. key = profile.llm_keys[{provider}]        -> 502 if absent
    │ 4. strip caller Authorization; inject provider.auth_header=<profile key>
    ▼
upstream provider (Gemini / OpenAI / Anthropic)
```

### Data Flow

1. Loader resolves each profile's `llm_keys[*].api_key_env` from env (fail closed).
2. `register_llm_routes` cross-checks every `llm_keys` provider name against the
   enabled `llm_providers`, failing closed at startup on a dangling reference.
3. Per request, the proxy resolves the profile by constant-time token comparison,
   looks up the profile's key for the requested provider, strips the caller
   token, and forwards with the injected key.

---

## Implementation Steps

### Phase 1: Config Schema
- [ ] `gateway/profile.py`: add `LlmKeyOverride(BaseModel)` — `api_key_env`
      (`ENV_NAME_RE`), `api_key: SecretStr` (default empty, `exclude=True`).
- [ ] Add `Profile.llm_keys: dict[str, LlmKeyOverride]` with a provider-slug
      key validator.

### Phase 2: Load-Time Resolution
- [ ] `gateway/loader.py`: in `_build_profile`, resolve each `llm_keys` env var;
      raise `ProfileConfigError` if unset/empty.

### Phase 3: Auth Resolution
- [ ] `gateway/auth.py`: add `resolve_profile_by_token(auth_header, registry)
      -> Profile | None` using `hmac.compare_digest`; handle missing/malformed
      headers and unresolved tokens.

### Phase 4: Proxy Wiring
- [ ] `gateway/llm_proxy.py`: `register_llm_routes(server, providers, profiles)`
      + startup cross-validation of `llm_keys` provider references.
- [ ] `_proxy_llm(request, providers, profiles)`: 404 / 401 / 502 handling,
      strip caller `Authorization`, inject profile key, audit log
      `profile=%s provider=%s`.
- [ ] `__init__.py`: pass `gateway_config.profiles` into `register_llm_routes`.

### Phase 5: Docs & Examples
- [ ] `examples/profiles-kagetora.yaml`: add `llm_keys` block.
- [ ] `docs/llm-proxying.md`: document required auth + per-profile keys + 401/502.

### Phase 6: Tests
- [ ] `tests/test_gateway_profile.py`: `LlmKeyOverride` + `llm_keys` validation.
- [ ] `tests/test_gateway_auth.py`: `resolve_profile_by_token`.
- [ ] `tests/test_llm_proxy.py`: cross-validation failure; 401/502/success proxy paths.
- [ ] `tests/test_gateway_loader.py` (or profile tests): `llm_keys` env fail-closed.

### Phase 7: Quality Gates
- [ ] `uv run ruff check src tests`
- [ ] `uv run mypy src`
- [ ] `uv run pytest -v`
- [ ] Gatehouse review

---

## File Changes

### New Files

| File | Purpose |
|------|---------|
| `.specify/specs/011-per-profile-llm-key/{spec,plan}.md` | Spec + plan |

### Modified Files

| File | Changes |
|------|---------|
| `gateway/profile.py` | `LlmKeyOverride` + `Profile.llm_keys` |
| `gateway/loader.py` | Resolve `llm_keys` env (fail closed) |
| `gateway/auth.py` | `resolve_profile_by_token` |
| `gateway/llm_proxy.py` | Authenticated proxy + profile key injection + strip Authorization + cross-check |
| `__init__.py` | Pass profiles to `register_llm_routes` |
| `examples/profiles-kagetora.yaml` | `llm_keys` example |
| `docs/llm-proxying.md` | Auth + per-profile key docs |
| `tests/test_gateway_profile.py`, `tests/test_gateway_auth.py`, `tests/test_llm_proxy.py` | New coverage |

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Caller token leaks upstream | High | Strip `Authorization` in `_proxy_llm` before forward; test asserts it |
| Existing unauthenticated callers break | Med | Intended hard cut (401); flagged as deployment follow-up |
| Dangling `llm_keys` provider ref | Med | Startup cross-validation fails closed |
| Timing oracle on token compare | Low | `hmac.compare_digest` per profile |

---

## Changelog

| Date | Changes |
|------|---------|
| 2026-07-03 | Initial plan |
