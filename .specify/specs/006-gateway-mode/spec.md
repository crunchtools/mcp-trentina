# Specification: Gateway Mode

> **Spec ID:** 006-gateway-mode
> **Status:** In Progress
> **Version:** 0.2.0
> **Author:** Scott McCarty
> **Date:** 2026-06-13

## Overview

Makes the per-consumer MCP gateway endpoint family (`POST /gateway/<profile>/mcp`)
the **single surface** for talking to airlock (Option C). Every tool a consumer
can reach — airlock's own web/fetch tools *and* every backend MCP server on the
`crunchtools` network — is surfaced through one per-consumer endpoint behind one
bearer token. The profile is the policy: one endpoint, one token, one YAML stanza
per agent.

Airlock's native tools (`safe_fetch_tool`, `quarantine_fetch_tool`,
`safe_search_tool`, …) are exposed as an **internal backend**: a profile backend
whose URL uses the `internal://<label>` scheme dispatches in-process to airlock's
own FastMCP tool registry instead of opening a streamable-http session. By
convention this backend is named `web`, so the tools surface as
`web__safe_fetch_tool`, `web__quarantine_fetch_tool`, etc. The result is that
*every* tool response — whether from `safe_fetch` against the open web or from
`mcp-atlassian` against a Confluence page — flows through the same gateway, and
(from Phase 2) the same L1/L2/L3 defense pipeline.

Tool-allowlist filtering on `tools/list` responses gives **real prompt-context
reduction** — unlike Claude Code's `permissions.deny` or Hermes's
`disabled_tools`, both of which gate execution but still ship full tool
definitions to the model.

The legacy `/mcp` web-tools surface is **deprecated** under Option C. It is still
registered by FastMCP's `mcp.run(transport="streamable-http")` (and on the
production base image, fastmcp 3.1.1, it returns 404 — see below), but no
consumer should target it: airlock's tools are reachable through the gateway's
`internal://` backend instead. Because `/mcp` and the gateway no longer need to
coexist as live surfaces, the fastmcp 3.1.1 routing collision that constrained
the earlier design is now irrelevant.

This spec covers the gateway transport surface: profile loader, bearer-token
auth, endpoint routing, tool allowlist filter, internal + http backend dispatch,
transparent tools/call passthrough. Defense pipeline application (L1/L2/L3 on
responses), audit log integration, and Cockpit UI come in later phases. See
`docs/gateway-design.md` for the full architecture and phasing.

---

## Endpoints

| Endpoint | Method | Status | Description |
|---|---|---|---|
| `/gateway/<profile>/mcp` | POST | **Canonical** | MCP endpoint, one per consumer profile. Routes to the profile's configured backends (http MCP servers + the `internal://` airlock-tools backend) with tool-name allowlist filtering. `GET`/`DELETE` return 405 (no session resumption). |
| `/mcp` | POST | **Deprecated** | The original web-tools surface. Still registered by FastMCP but not for consumer use; airlock's tools are reached via the gateway's `internal://` backend. On the production base image (fastmcp 3.1.1) it returns 404 — deliberate, not a regression. |

The gateway endpoint is not a "tool" in the MCP sense — it's an HTTP endpoint
family that itself speaks MCP to consumers. `tools/list` returns the filtered,
namespaced union of all backend tools (internal + http); `tools/call` dispatches
to the appropriate backend.

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
- Backend URL scheme is scheme-discriminated: `http(s)://` for remote streamable-http MCP servers, `internal://<label>` for airlock's in-process tool registry. SSE and stdio are rejected at profile-load time. The `internal://` label must match `^[a-z][a-z0-9-]*$` so the namespace stays well-formed.
- The internal backend executes airlock's own already-trusted tool coroutines in-process — no new network surface, no new credential. It is subject to the same per-profile allow/deny filter and call-time re-check as any http backend.
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
| `gateway/router.py` | JSON-RPC dispatch (`initialize`, `tools/list`, `tools/call`, `ping`) per profile; dispatches each backend by URL scheme (http vs internal) |
| `gateway/internal.py` | Internal backend: walks airlock's own FastMCP tool registry, exposing `list_internal_tools()` / `call_internal_tool()` with the same return types as the http backend |
| `gateway/app.py` | Starlette app exposing `/gateway/{profile}/mcp` routes |
| `gateway/errors.py` | Gateway-specific error responses (constant-time auth fail, scrubbed messages) |
| `tests/test_gateway_profile.py` | Profile model + loader tests (incl. `internal://` scheme validation) |
| `tests/test_gateway_auth.py` | Bearer-token verification tests |
| `tests/test_gateway_filter.py` | Allowlist filter tests |
| `tests/test_gateway_router.py` | JSON-RPC dispatch tests, incl. mixed http+internal aggregation and internal-routed calls |
| `tests/test_gateway_internal.py` | Internal-backend dispatch tests (list/call/error mapping + real-server smoke test) |

### Modified Files

| File | Changes |
|------|---------|
| `__init__.py` | `_run_with_gateway()`: when `AIRLOCK_GATEWAY_ENABLED=true`, register the gateway `custom_route` AND bind airlock's FastMCP server as the internal-tool backend (`register_internal_server`) before `mcp.run(...)` |
| `gateway/profile.py` | `Backend.url` validator accepts `internal://<label>` alongside `http(s)://`; adds `Backend.is_internal` |
| `config.py` | Add `AIRLOCK_GATEWAY_ENABLED`, `AIRLOCK_PROFILES_PATH` env vars |
| `pyproject.toml` | `pyyaml>=6.0` dependency; version bump |

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
3. **MCP `resources/*` and `prompts/*` methods**: deferred to v1.1 per design doc. The gateway returns method-not-found for these for now.

> **Note on the fastmcp 3.1.1 routing collision (resolved by Option C):** the
> earlier design worried that registering the gateway `custom_route` made the
> FastMCP `/mcp` endpoint 404 on the production base image. Under Option C `/mcp`
> is deprecated and unused, so its 404 is harmless — the collision no longer
> constrains anything and the `AIRLOCK_GATEWAY_ENABLED` flag can be flipped on
> without bumping fastmcp.

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | 2026-06-13 | Initial draft — Phase 1 scope only |
| 0.2.0 | 2026-06-13 | Option C: gateway is the single surface; `/mcp` deprecated; airlock's own tools exposed via the `internal://` backend; routing-collision known-issue retired. |
