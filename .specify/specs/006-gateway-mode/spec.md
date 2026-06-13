# Specification: Gateway Mode

> **Spec ID:** 006-gateway-mode
> **Status:** In Progress
> **Version:** 0.1.0
> **Author:** Scott McCarty
> **Date:** 2026-06-13

## Overview

Adds a per-consumer MCP gateway endpoint family (`POST /gateway/<profile>/mcp`)
to airlock alongside the existing `/mcp` web-tools surface. Each profile defines
which backend MCP servers a consumer can reach, which of their tools are
allowed, and which defense layers (L1/L2/L3) apply to responses. Tool-allowlist
filtering on `tools/list` responses gives **real prompt-context reduction** —
unlike Claude Code's `permissions.deny` or Hermes's `disabled_tools`, both of
which gate execution but still ship full tool definitions to the model.

This spec covers **Phase 1** only: profile loader, bearer-token auth, endpoint
routing, tool allowlist filter, transparent tools/call passthrough. Defense
pipeline (L1/L2/L3 on responses), audit log integration, and Cockpit UI come
in Phases 2-4. See `docs/gateway-design.md` for the full architecture and
phasing.

---

## New Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/gateway/<profile>/mcp` | POST, GET, DELETE | MCP streamable-http endpoint, one per consumer profile. Routes to the profile's configured backend MCP servers with tool-name allowlist filtering. |

Not a "tool" in the MCP sense — a new HTTP endpoint family that itself exposes
MCP protocol to consumers. `tools/list` returns the filtered union of backend
tools; `tools/call` proxies to the appropriate backend.

---

## Security Considerations

### Layer 1 — Token Protection
- Profile bearer tokens stored as `pydantic.SecretStr`.
- Tokens read from env vars named in `auth.bearer_token_env` field of profile config — never hardcoded in YAML.
- Token values scrubbed from all error messages (existing `errors.py` pattern extended to cover gateway errors).

### Layer 2 — Input Validation
- New Pydantic models for profile config in `gateway/profile.py` (`Profile`, `Backend`, `DefenseConfig`, `AuthConfig`), all with `extra="forbid"`.
- Tool-name allowlist patterns validated as restricted glob (no regex, no shell metacharacters; only `*`, alphanumeric, underscore, hyphen).
- Bearer tokens validated as non-empty constant-time-compared strings.
- Profile name in URL path validated against `^[a-z][a-z0-9-]*$` to prevent path traversal in route matching.

### Layer 3 — API Hardening
- TLS for backend MCP connections when URL scheme is `https://` (loopback `http://` is fine on the `crunchtools` podman network).
- Timeouts on all backend MCP calls (configurable per profile, default 30s).
- Backend response size limit (configurable, default 10 MB; rejects oversized).
- Failed backend connection emits 502 to consumer, never silently retries past N attempts.

### Layer 4 — Dangerous Operation Prevention
- Gateway code never executes user content — it's a transparent forwarder for Phase 1.
- No shell execution, no `eval()`/`exec()`.
- No filesystem writes from the gateway path (audit log writes come in Phase 3 via existing SQLite layer).
- Profile YAML loaded with `yaml.safe_load` only (never `yaml.load`).

### Layer 5 — Supply Chain Security
- `pyyaml` added as direct dependency (was implicit via FastMCP); pinned to `>=6.0`.
- `mcp` package already a transitive dep via `fastmcp>=2.0`; `mcp.client.streamable_http` reused for backend connections.
- No new SDKs.

---

## Module Changes

### New Files

| File | Purpose |
|------|---------|
| `gateway/__init__.py` | Subpackage exports |
| `gateway/profile.py` | Pydantic models for profile config (`Profile`, `Backend`, `DefenseConfig`, `AuthConfig`) |
| `gateway/loader.py` | YAML config loader with env-var token resolution |
| `gateway/auth.py` | Bearer-token verification (constant-time compare) |
| `gateway/backend.py` | Backend MCP connection management via `mcp.client.streamable_http` |
| `gateway/filter.py` | `tools/list` response allowlist filter (glob-pattern matching) |
| `gateway/router.py` | JSON-RPC dispatch (`initialize`, `tools/list`, `tools/call`, `ping`) per profile |
| `gateway/app.py` | Starlette app exposing `/gateway/{profile}/mcp` routes |
| `gateway/errors.py` | Gateway-specific error responses (constant-time auth fail, scrubbed messages) |
| `tests/test_gateway_profile.py` | Profile model + loader tests |
| `tests/test_gateway_auth.py` | Bearer-token verification tests |
| `tests/test_gateway_filter.py` | Allowlist filter tests |
| `tests/test_gateway_router.py` | JSON-RPC dispatch tests (mocked backend calls) |

### Modified Files

| File | Changes |
|------|---------|
| `server.py` | Mount gateway Starlette app alongside the FastMCP streamable-http app under a parent Starlette container |
| `config.py` | Add `AIRLOCK_GATEWAY_ENABLED`, `AIRLOCK_PROFILES_PATH` env vars |
| `pyproject.toml` | Add `pyyaml>=6.0` to dependencies; bump version to 0.4.0 |

---

## Testing Requirements

### Mocked Tests (no live MCP backends)

- [ ] `TestProfileLoading` — valid YAML, missing tokens, bad allowlist patterns, schema violations.
- [ ] `TestAuthVerification` — valid token, wrong token, missing header, malformed header, constant-time-compare verified by timing assertion sanity check.
- [ ] `TestAllowlistFilter` — `*` wildcard, prefix glob, suffix glob, substring glob, multiple patterns, deny override.
- [ ] `TestRouterDispatch` — `initialize` response, `tools/list` aggregation across mocked backends, `tools/call` routing to correct backend by namespaced tool name, `ping` response, unknown method 405.
- [ ] `TestEndpointIntegration` — Starlette test client end-to-end: POST → auth check → dispatch → mocked backend → response.
- [ ] Adversarial: profile name with `../`, allowlist pattern with regex metacharacters, oversized backend response.

### Tool Count Update

Phase 1 adds zero `@mcp.tool()`-registered tools to the existing FastMCP surface — the gateway endpoints are independent of the FastMCP tool registry. The `test_tool_count` assertion stays at its current value.

---

## Dependencies

- Depends on: 005-safe-search (current head; no functional dependency, but ensures we're branching off the latest defense pipeline)
- Blocks: 007 (gateway L1/L2/L3 defense application — Phase 2), 008 (gateway audit + Cockpit — Phase 3-4)

---

## Open Questions

1. **Should Phase 1 require `AIRLOCK_GATEWAY_ENABLED=true` to mount the routes?** Recommend yes — feature-flagged rollout, default off, no behavior change for existing deployments until flipped.
2. **Profile reload behavior**: hot-reload on YAML file change (Phase 4 — Cockpit editor needs this), or restart-only for Phase 1? Recommend restart-only for Phase 1; revisit in Phase 4.
3. **MCP `resources/*` and `prompts/*` methods**: deferred to v1.1 per design doc, not Phase 1. Phase 1 returns method-not-found for these.

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | 2026-06-13 | Initial draft — Phase 1 scope only |
