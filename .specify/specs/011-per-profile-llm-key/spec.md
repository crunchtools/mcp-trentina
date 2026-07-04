# Specification: Per-Profile LLM Proxy Keys

> **Spec ID:** 011-per-profile-llm-key
> **Status:** Draft
> **Version:** 0.1.0
> **Author:** Scott McCarty
> **Date:** 2026-07-03

## Overview

The LLM reverse proxy (`/llm/{provider}/{path}`) currently injects a single
global provider key for every caller, so all agents share one rate-limit bucket
and their token spend is indistinguishable. This feature authenticates each
proxy request against the caller's existing gateway bearer token and injects
**that profile's** provider key, giving each consumer (Kagetora, Takeda) its own
key, its own rate-limit quota, and per-consumer token accounting via the
provider's own dashboard. Closes #53.

---

## New Tools

None. This is a transport/config change to the existing `/llm/{provider}/{path}`
reverse-proxy endpoint — no new MCP tools.

| Endpoint | Method | Change |
|----------|--------|--------|
| `/llm/{provider}/{path:path}` | GET/POST/PUT/DELETE | Now requires a valid profile bearer token; injects the caller profile's provider key |

---

## Security Considerations

### Layer 1 — Token Protection
- New per-profile `llm_keys[*].api_key` stored as Pydantic `SecretStr`, resolved
  from env at load time, `exclude=True` so it never serializes.
- The incoming `Authorization` header (the caller's profile bearer token) MUST be
  stripped before forwarding upstream — it must never leak to Gemini/OpenAI/etc.
  (The Matrix proxy still forwards `Authorization`, so this strip is local to the
  LLM proxy, not the shared header helper.)
- Profile resolution uses constant-time `hmac.compare_digest` against each
  profile token (reuse of the existing `verify_bearer` primitive).

### Layer 2 — Input Validation
- New `LlmKeyOverride` Pydantic model (`extra="forbid"`): `api_key_env` validated
  against `ENV_NAME_RE`.
- New `Profile.llm_keys: dict[str, LlmKeyOverride]`; provider-name keys validated
  against a provider-slug regex.
- Startup cross-validation: every `llm_keys` provider name must correspond to a
  configured, enabled `llm_providers` entry, else fail closed
  (`ProfileConfigError`).

### Layer 3 — API Hardening
- The proxy endpoint gains mandatory authentication. Requests with a missing or
  unknown bearer token are rejected with `401` before any upstream contact —
  closing the current unauthenticated-spend hole.
- Existing path-traversal sanitization (`sanitize_proxy_path`) is unchanged.

### Layer 4 — Dangerous Operation Prevention
- No file/shell/eval surface. Keys are resolved from environment variables only;
  no key material is read from request bodies or paths.

---

## Behavior

| Condition | Result |
|-----------|--------|
| Unknown/disabled `{provider}` | `404` |
| Missing or malformed `Authorization` | `401` |
| Token matches no profile | `401` |
| Authenticated profile has no `llm_keys` entry for `{provider}` | `502` (no key configured) |
| Authenticated profile has a key for `{provider}` | Inject profile key, strip caller `Authorization`, forward |

The Q-Agent is unaffected — it calls providers directly (not through `/llm/`) and
continues to use the global `GEMINI_API_KEY`.

---

## Module Changes

### New Files

| File | Purpose |
|------|---------|
| `.specify/specs/011-per-profile-llm-key/spec.md` | This spec |
| `.specify/specs/011-per-profile-llm-key/plan.md` | Implementation plan |

### Modified Files

| File | Changes |
|------|---------|
| `gateway/profile.py` | Add `LlmKeyOverride` model + `Profile.llm_keys` field + validator |
| `gateway/loader.py` | Resolve `llm_keys` env vars (fail closed) in `_build_profile` |
| `gateway/auth.py` | Add `resolve_profile_by_token(auth_header, registry)` |
| `gateway/llm_proxy.py` | `register_llm_routes`/`_proxy_llm` take `profiles`; authenticate, select profile key, strip `Authorization`; startup cross-check |
| `__init__.py` | Pass `gateway_config.profiles` to `register_llm_routes` |
| `examples/profiles-kagetora.yaml` | Add `llm_keys` example |
| `docs/llm-proxying.md` | Document auth requirement + per-profile keys + 401/502 semantics |

---

## Testing Requirements

### Mocked API Tests
- [ ] `resolve_profile_by_token`: match, no-match, missing header, malformed header
- [ ] `register_llm_routes` cross-validation: profile referencing an unknown/disabled provider fails closed
- [ ] Proxy `401` on missing token, `401` on unknown token
- [ ] Proxy `502` when authenticated profile has no key for the provider
- [ ] Proxy success (TestClient + monkeypatched httpx client): profile key injected, caller `Authorization` stripped

### Input Validation Tests
- [ ] `LlmKeyOverride`: valid, `extra="forbid"`, bad `api_key_env`
- [ ] `Profile.llm_keys`: bad provider-slug key rejected
- [ ] Loader: `llm_keys` env unset fails closed

### Tool Count Update
- [ ] N/A — no tool count change

---

## Dependencies

- Depends on: 006-gateway-mode (profiles/auth), 010-streamable-http (proxy wiring)
- Relates to: 009-per-profile-provider (same per-profile override shape)
- Blocks: none

---

## Open Questions

None — routing (bearer-resolved profile, no profile in URL), unauth handling
(401), and key fallback (explicit per-profile key required, no global fallback)
were resolved during planning.

---

## Deployment Notes (outside this repo)

- Provision `KAGETORA_GEMINI_API_KEY` / `TAKEDA_GEMINI_API_KEY` on lotor and add
  `llm_keys` blocks to the production `profiles.yaml`.
- Takeda currently connects direct to `/mcp` with no gateway profile; it needs a
  profile + bearer token, and its Gemini client must send that token to `/llm/`.
- Each agent's LLM client must present its profile bearer token on `/llm/`
  requests.

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | 2026-07-03 | Initial draft |
