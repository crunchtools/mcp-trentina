# Implementation Plan: Gateway Mode — Phase 1 + Option C

> **Spec ID:** 006-gateway-mode
> **Status:** In Progress
> **Last Updated:** 2026-06-13

## Summary

Phase 1 added a `gateway/` subpackage exposing `/gateway/<profile>/mcp` endpoints
that proxy to backend MCP servers with bearer-token auth and tool-allowlist
filtering on `tools/list` responses.

**Option C** folds airlock's own tools into that same gateway as an in-process
`internal://` backend and deprecates the standalone `/mcp` web-tools surface, so
the gateway becomes the single per-consumer endpoint for everything. No defense
pipeline application yet — that's Phase 2.

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
FastMCP app  —  custom_route("/gateway/{profile}/mcp")  (gateway/app.py)
    │  ┌──────────────────┐
    │  │ auth.py verify   │  bearer token vs profile config
    │  ├──────────────────┤
    │  │ profile lookup   │  loader.py registry
    │  ├──────────────────┤
    │  │ router.py        │  JSON-RPC method dispatch
    │  │                  │
    │  │  initialize ────────► return gateway server info
    │  │  tools/list ────────► aggregate across backends, filter.py applies allowlist
    │  │  tools/call ────────► dispatch by backend.is_internal
    │  │  ping ──────────────► return pong
    │  │  (other) ───────────► method-not-found
    │  └──────────────────┘
    ▼
   scheme dispatch
    ├── http(s):// ──► backend.py  ──► remote MCP server (mcp-slack:8005, …)
    └── internal:// ─► internal.py ──► airlock's own FastMCP tool registry (in-process)
    │
    │  response (both paths return the same dict / BackendCall shape)
    ▼
filter.py (for tools/list) — drops tools not in profile allowlist; namespaces <backend>__<tool>
    │
    ▼
Consumer
```

The deprecated `/mcp` web-tools endpoint is still registered by FastMCP's
`mcp.run()` but is not a consumer surface under Option C — airlock's tools are
reached through the `internal://` backend above.

### Why custom_route, not a parent Starlette app

Phase 1 originally planned a parent Starlette wrapper, but the gateway is wired
via FastMCP's `custom_route("/gateway/{profile}/mcp")` decorator instead — it
keeps FastMCP's internal routing intact and needs no app composition. Under
Option C the gateway is the only live surface, so there is no parallel `/mcp`
surface to preserve and no routing-collision concern.

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

### Step 11 (Option C): Internal-tool backend

- [x] `gateway/profile.py`: `Backend.url` validator accepts `internal://<label>` (slug-validated) alongside `http(s)://`; add `Backend.is_internal` property.
- [x] `gateway/internal.py`: module-level bound FastMCP server + `register_internal_server()`, `list_internal_tools()`, `call_internal_tool()` returning the same `dict` / `BackendCall` shapes as `backend.py` (reusing its `_serialize_tool` / `_serialize_content_block`).
- [x] `gateway/router.py`: `_route_tools_list` and `_route_tools_call` dispatch on `backend.is_internal` (internal registry vs streamable-http). Namespacing and allowlist logic unchanged.
- [x] `gateway/__init__.py`: export the internal-tool functions.
- [x] `__init__.py` `_run_with_gateway()`: call `register_internal_server(mcp)` before `mcp.run(...)`.
- [x] `tests/test_gateway_internal.py` + extend `tests/test_gateway_router.py` (mixed http+internal) and `tests/test_gateway_profile.py` (`internal://` validation).

### Step 12: Quality gates

- [x] `uv run ruff check src tests` (gateway + new tests clean)
- [x] `uv run mypy src` (gateway clean)
- [x] `uv run pytest -v` (332 passed, 32 pre-existing skips)
- [ ] `gourmand --full .`
- [ ] `podman build -f Containerfile .`

### Step 13: Deploy to lotor (Option C cutover)

- [ ] Push branch → GHA build (or build the overlay image) → image carrying Option C
- [ ] Provision `/srv/mcp-trentina.crunchtools.com/config/profiles.yaml` with real `josui` + `kagetora` profiles, each carrying the `web` (`internal://web`) backend + their http backend matrix
- [ ] Generate `AIRLOCK_GATEWAY_JOSUI_TOKEN` + `AIRLOCK_GATEWAY_KAGETORA_TOKEN` on lotor (`secrets.token_hex(32)`), add to `mcp-trentina.env`
- [ ] Add `AIRLOCK_GATEWAY_ENABLED=true` + `AIRLOCK_PROFILES_PATH=/etc/airlock/profiles.yaml`; mount profiles.yaml into the container
- [ ] systemctl restart; verify `/gateway/<profile>/mcp` lists tools across an http backend AND `web__safe_fetch_tool`; confirm `/mcp` 404 is deliberate
- [ ] **Cut Kagetora over first** (smaller blast radius, autonomous agent): one `mcp_servers:` entry in Hermes `config.yaml`; verify prompt-token count drops from ~146K toward <50K
- [ ] **Then Josui**: one `airlock-gateway` entry in `~/.claude.json`; shrink the SSH tunnel from 10 LocalForwards to one (8019)
- [ ] Clean up: delete the `gateway-test` profile, `/root/.airlock-gateway-test-token`, the `phase1` overlay image, and `Containerfile.gateway-overlay`

---

## File Changes

### New Files

| File | Purpose |
|------|---------|
| `src/mcp_trentina_crunchtools/gateway/__init__.py` | Subpackage exports |
| `src/mcp_trentina_crunchtools/gateway/profile.py` | Pydantic profile models |
| `src/mcp_trentina_crunchtools/gateway/loader.py` | YAML loader + env resolution |
| `src/mcp_trentina_crunchtools/gateway/auth.py` | Bearer-token check |
| `src/mcp_trentina_crunchtools/gateway/backend.py` | Backend MCP connection pool |
| `src/mcp_trentina_crunchtools/gateway/filter.py` | Tools/list allowlist filter |
| `src/mcp_trentina_crunchtools/gateway/router.py` | JSON-RPC dispatch |
| `src/mcp_trentina_crunchtools/gateway/app.py` | Starlette gateway app |
| `src/mcp_trentina_crunchtools/gateway/errors.py` | Gateway error responses |
| `tests/test_gateway_profile.py` | Profile + loader tests |
| `tests/test_gateway_auth.py` | Auth tests |
| `tests/test_gateway_filter.py` | Filter tests |
| `tests/test_gateway_router.py` | Router tests |
| `tests/test_gateway_app.py` | End-to-end integration tests |

### Modified Files

| File | Changes |
|------|---------|
| `src/mcp_trentina_crunchtools/server.py` | Wrap FastMCP app in parent Starlette; mount gateway routes when enabled |
| `src/mcp_trentina_crunchtools/config.py` | Add `AIRLOCK_GATEWAY_ENABLED`, `AIRLOCK_PROFILES_PATH` |
| `pyproject.toml` | Add `pyyaml>=6.0`; bump `version` to `0.4.0` |

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Backend MCP connection leaks under load | Med | Phase 1 opens a fresh session per call (no pool); `async with` guarantees teardown. Pooling is a Phase 2 optimization. |
| ~~FastMCP `/mcp` vs gateway custom-route collision (3.1.1)~~ | ~~High~~ | **Retired by Option C.** `/mcp` is deprecated and unused; its 404 on 3.1.1 is harmless. No fastmcp bump needed. |
| Internal backend executing untrusted args in-process | Med | The internal backend only invokes airlock's own already-trusted tool coroutines, subject to the same per-profile allow/deny filter and call-time re-check as http backends. No new code path executes consumer content. |
| Allowlist patterns allowing path traversal in tool names | Med | Glob validator rejects `..`, `/`, leading hyphen, regex metachars. Tested adversarially. |
| Bearer tokens leaked in logs | High | Profile model uses `SecretStr`; errors.py scrubbed; mypy enforces no `__repr__` leak. Test asserts log absence. |
| Profile YAML file not present on container start | Low | When `AIRLOCK_GATEWAY_ENABLED=true` but file missing → fail closed at startup with clear error log. When disabled → no profile load attempted. |

---

## Changelog

| Date | Changes |
|------|---------|
| 2026-06-13 | Initial Phase 1 plan |
| 2026-06-13 | Option C: internal-tool backend steps; routing-collision risk retired; migration step rewritten as the Kagetora-then-Josui single-endpoint cutover |
