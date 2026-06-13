# Implementation Plan: Gateway Mode — Phase 1

> **Spec ID:** 006-gateway-mode
> **Status:** In Progress
> **Last Updated:** 2026-06-13

## Summary

Phase 1: add a `gateway/` subpackage that exposes `/gateway/<profile>/mcp` endpoints
alongside airlock's existing `/mcp` web-tools surface. Transparent proxy to
backend MCP servers with bearer-token auth and tool-allowlist filtering on
`tools/list` responses. No defense pipeline application yet — that's Phase 2.

---

## Architecture

### Request Flow (Phase 1)

```
Consumer (Josui / Kagetora / future Takeda)
    │
    │  POST /gateway/<profile>/mcp   (Authorization: Bearer <token>)
    │  Content-Type: application/json
    │  Body: JSON-RPC 2.0 request
    ▼
Starlette parent app  (server.py)
    │
    │  route match on /gateway/{profile}/mcp
    ▼
gateway/app.py  GatewayHandler
    │  ┌──────────────────┐
    │  │ auth.py verify   │  bearer token vs profile config
    │  ├──────────────────┤
    │  │ profile lookup   │  loader.py registry
    │  ├──────────────────┤
    │  │ router.py        │  JSON-RPC method dispatch
    │  │                  │
    │  │  initialize ────────► return gateway server info
    │  │  tools/list ────────► aggregate from backends, filter.py applies allowlist
    │  │  tools/call ────────► backend.py routes to correct backend
    │  │  ping ──────────────► return pong
    │  │  (other) ───────────► method-not-found
    │  └──────────────────┘
    ▼
backend.py
    │  mcp.client.streamable_http connection pool (one per backend per profile)
    ▼
Backend MCP server (mcp-slack:8005, mcp-mediawiki:8016, etc.)
    │
    │  response
    ▼
filter.py (for tools/list) — drops tools not in profile allowlist
    │
    ▼
Consumer
```

### Why Starlette parent app

FastMCP exposes `mcp.streamable_http_app()` returning a Starlette app. To add
custom `/gateway/{profile}/mcp` routes we wrap that app inside a parent Starlette
container that adds our routes at top-level priority and mounts the FastMCP app
at `/` for everything else (so the existing `/mcp` web-tools endpoint keeps
working unchanged).

### Why raw JSON-RPC instead of FastMCP-per-profile

For Phase 1 transparency, raw JSON-RPC dispatch is simpler — we forward
verbatim. Spinning up a FastMCP instance per profile with dynamically-registered
proxy tools is feasible but adds initialization overhead, makes per-request
auth check awkward, and complicates the future defense-pipeline injection point
(Phase 2). Raw JSON-RPC keeps the chokepoint visible.

---

## Implementation Steps

### Step 1: Add `pyyaml` dep + bump version

- [x] `pyproject.toml`: add `pyyaml>=6.0`; bump `version = "0.4.0"`.

### Step 2: Profile config models

- [x] `gateway/profile.py`: Pydantic v2 models with `extra="forbid"` — `Profile`, `Backend`, `DefenseConfig`, `AuthConfig`.
- [x] Bearer token typed as `SecretStr`, not in YAML.
- [x] Allowlist/denylist as `list[str]` with restricted-glob validator (no regex metachars).

### Step 3: YAML loader

- [x] `gateway/loader.py`: `load_profiles(path: Path) -> dict[str, Profile]` using `yaml.safe_load`.
- [x] Resolves `auth.bearer_token_env` → reads env var → constructs `SecretStr`.
- [x] Raises `ProfileConfigError` on missing env vars (fail-closed at startup).
- [x] Module-level `get_profile_registry()` for singleton access; lazy load on first call.

### Step 4: Bearer-token auth

- [x] `gateway/auth.py`: `verify_bearer(request, profile) -> None` raises `AuthError` on mismatch.
- [x] Constant-time compare via `hmac.compare_digest`.
- [x] Returns 401 with no token-content disclosure on failure.

### Step 5: Backend connection management

- [x] `gateway/backend.py`: `BackendPool` class managing `mcp.client.streamable_http` connections.
- [x] Lazy connect on first call to a backend; cache the open session per profile+backend.
- [x] `call_tool(profile, backend_name, tool_name, args) -> dict` for tools/call routing.
- [x] `list_tools(profile, backend_name) -> list[dict]` for tools/list aggregation.
- [x] Per-call timeout (from `Backend.timeout_seconds`, default 30).

### Step 6: Allowlist filter

- [x] `gateway/filter.py`: `filter_tools(tools: list[dict], allow: list[str], deny: list[str]) -> list[dict]`.
- [x] Glob matching via `fnmatch.fnmatchcase` (already-validated restricted glob).
- [x] Deny wins over allow.
- [x] Tool names namespaced as `<backend>__<tool>` in the aggregated list.

### Step 7: JSON-RPC router

- [x] `gateway/router.py`: `route(profile, jsonrpc_request) -> jsonrpc_response`.
- [x] Methods supported: `initialize`, `tools/list`, `tools/call`, `ping`.
- [x] Other methods return JSON-RPC error `-32601` (method not found).
- [x] Namespaced tool names parsed into `(backend, tool)` for routing.

### Step 8: Starlette app

- [x] `gateway/app.py`: `gateway_app(registry) -> Starlette` with route `POST /gateway/{profile}/mcp`.
- [x] Phase 1 supports `POST` only; `GET`/`DELETE` for session management return 405 (defer to Phase 2).
- [x] Auth handler runs before dispatch; 401 short-circuit.

### Step 9: Mount in server.py

- [x] Wrap existing `mcp.streamable_http_app()` in a parent Starlette app.
- [x] Add gateway routes when `AIRLOCK_GATEWAY_ENABLED=true`.
- [x] When env var unset/false: parent app is identical to old behavior (gateway routes absent).

### Step 10: Tests

- [x] `tests/test_gateway_profile.py`: profile loading happy path + 6 error cases.
- [x] `tests/test_gateway_auth.py`: bearer-token cases.
- [x] `tests/test_gateway_filter.py`: glob-pattern cases incl. deny override.
- [x] `tests/test_gateway_router.py`: method dispatch + tool routing with mocked `BackendPool`.
- [x] `tests/test_gateway_app.py`: Starlette test-client integration.

### Step 11: Quality gates

- [ ] `uv run ruff check src tests`
- [ ] `uv run mypy src`
- [ ] `uv run pytest -v`
- [ ] `gourmand --full .`
- [ ] `podman build -f Containerfile .`

### Step 12: Deploy to lotor

- [ ] Push branch → GHA build → image at `quay.io/crunchtools/mcp-airlock:latest`
- [ ] Provision `/srv/mcp-airlock.crunchtools.com/config/profiles.yaml` with `josui` + `kagetora` profiles
- [ ] Add `AIRLOCK_GATEWAY_ENABLED=true` and `AIRLOCK_PROFILES_PATH=/etc/airlock/profiles.yaml` to env file
- [ ] Mount profiles.yaml into container at /etc/airlock/profiles.yaml
- [ ] systemctl restart, verify both endpoints respond, validate tool allowlist with a probe

---

## File Changes

### New Files

| File | Purpose |
|------|---------|
| `src/mcp_airlock_crunchtools/gateway/__init__.py` | Subpackage exports |
| `src/mcp_airlock_crunchtools/gateway/profile.py` | Pydantic profile models |
| `src/mcp_airlock_crunchtools/gateway/loader.py` | YAML loader + env resolution |
| `src/mcp_airlock_crunchtools/gateway/auth.py` | Bearer-token check |
| `src/mcp_airlock_crunchtools/gateway/backend.py` | Backend MCP connection pool |
| `src/mcp_airlock_crunchtools/gateway/filter.py` | Tools/list allowlist filter |
| `src/mcp_airlock_crunchtools/gateway/router.py` | JSON-RPC dispatch |
| `src/mcp_airlock_crunchtools/gateway/app.py` | Starlette gateway app |
| `src/mcp_airlock_crunchtools/gateway/errors.py` | Gateway error responses |
| `tests/test_gateway_profile.py` | Profile + loader tests |
| `tests/test_gateway_auth.py` | Auth tests |
| `tests/test_gateway_filter.py` | Filter tests |
| `tests/test_gateway_router.py` | Router tests |
| `tests/test_gateway_app.py` | End-to-end integration tests |

### Modified Files

| File | Changes |
|------|---------|
| `src/mcp_airlock_crunchtools/server.py` | Wrap FastMCP app in parent Starlette; mount gateway routes when enabled |
| `src/mcp_airlock_crunchtools/config.py` | Add `AIRLOCK_GATEWAY_ENABLED`, `AIRLOCK_PROFILES_PATH` |
| `pyproject.toml` | Add `pyyaml>=6.0`; bump `version` to `0.4.0` |

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Backend MCP connection leaks under load | Med | `BackendPool` uses `async with` context managers; verified by mocked-client test that asserts on `__aexit__` calls. |
| FastMCP's Starlette app conflicts with gateway routes | High | Mount FastMCP at `/` after gateway routes are registered — Starlette matches first-match-wins, so `/gateway/*` matches before `/`. Verified by integration test. |
| Allowlist patterns allowing path traversal in tool names | Med | Glob validator rejects `..`, `/`, leading hyphen, regex metachars. Tested adversarially. |
| Bearer tokens leaked in logs | High | Profile model uses `SecretStr`; errors.py scrubbed; mypy enforces no `__repr__` leak. Test asserts log absence. |
| Profile YAML file not present on container start | Low | When `AIRLOCK_GATEWAY_ENABLED=true` but file missing → fail closed at startup with clear error log. When disabled → no profile load attempted. |

---

## Changelog

| Date | Changes |
|------|---------|
| 2026-06-13 | Initial Phase 1 plan |
