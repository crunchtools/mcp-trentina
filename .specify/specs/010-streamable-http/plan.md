# Implementation Plan: Streamable HTTP Transport for Gateway

> **Spec ID:** 010-streamable-http
> **Status:** Planning
> **Last Updated:** 2026-07-02

## Summary

Bridge Trentina's custom gateway proxy with FastMCP's built-in
`StreamableHTTPSessionManager` to support persistent MCP sessions and
server-initiated `tools/listChanged` notifications. The key challenge is
preserving Trentina's per-profile auth, tool namespacing, allowlists, parameter
guards, and circuit breaker while delegating transport-level session management to
FastMCP.

---

## Architecture

### Current Flow (Phase 1: Stateless)

```
Agent (Claude Code)
    │ POST /gateway/josui/mcp
    ▼
app.py (_handle_post)
    │ auth, parse JSON-RPC
    ▼
router.py (route_jsonrpc)
    │ dispatch: initialize/tools/list/tools/call
    ▼
backend.py (list_backend_tools / call_backend_tool)
    │ fresh streamable-http session per call
    ▼
Backend MCP Server (GitHub, Jira, Slack, etc.)
```

### Target Flow (Phase 2: Streamable HTTP)

```
Agent (Claude Code)
    │ POST/GET/DELETE /gateway/josui/mcp
    ▼
app.py (streamable HTTP handler)
    │ auth, session lookup/create
    ▼
sessions.py (SessionRegistry)
    │ per-profile session tracking, TTL
    ▼
router.py (route_jsonrpc — unchanged dispatch logic)
    │ dispatch: initialize/tools/list/tools/call
    │ listChanged: true in initialize response
    ▼
backend.py (unchanged — fresh per call)
    ▼
Backend MCP Server

    ╔══════════════════════════════════╗
    ║ Circuit breaker state change     ║
    ║ circuit.py → sessions.py         ║
    ║ → broadcast tools/listChanged    ║
    ║ → active GET streams for profile ║
    ╚══════════════════════════════════╝
```

### Data Flow for tools/listChanged

1. Backend fails 3 consecutive times → circuit opens
2. `circuit.py` calls registered callback: `on_circuit_state_change(url, old_state, new_state)`
3. `sessions.py` looks up which profiles include that backend URL
4. For each affected profile, iterates active sessions
5. Pushes `{"jsonrpc": "2.0", "method": "notifications/tools/listChanged"}` to each session's write stream
6. Agent receives notification on GET stream (or interleaved in POST response)
7. Agent re-requests `tools/list` → gets updated tool set (dead backend's tools excluded)

---

## Implementation Steps

### Phase 1: Session Registry (`gateway/sessions.py`)

- [ ] Create `SessionRegistry` class: tracks sessions per profile
- [ ] Session dataclass: session_id, profile_name, created_at, last_access, transport reference
- [ ] `create_session(profile_name)` → session_id
- [ ] `get_session(session_id)` → session or None
- [ ] `delete_session(session_id)`
- [ ] `get_sessions_for_profile(profile_name)` → list of sessions
- [ ] `broadcast_to_profile(profile_name, notification)` — send to all active sessions
- [ ] TTL expiry: background task or lazy cleanup on access
- [ ] Max sessions per profile enforcement

### Phase 2: Circuit Breaker Callbacks (`gateway/circuit.py`)

- [ ] Add `on_state_change` callback registration to `CircuitBreaker`
- [ ] Call callback on every state transition with (url, old_state, new_state)
- [ ] Keep existing logging — callbacks are additive

### Phase 3: Gateway HTTP Handler (`gateway/app.py`)

- [ ] Replace `_handle_post` with Streamable HTTP-aware handler
- [ ] Accept POST (existing), GET (new: SSE stream), DELETE (new: session teardown)
- [ ] On POST `initialize`: create session, return `Mcp-Session-Id` header
- [ ] On POST with session ID: validate session, dispatch to router
- [ ] On POST without session ID (non-initialize): stateless mode (backwards compat)
- [ ] On GET with session ID: open SSE stream, register for notifications
- [ ] On DELETE with session ID: tear down session, return 204
- [ ] Auth required on all methods (GET/DELETE also check bearer token)

### Phase 4: Router Updates (`gateway/router.py`)

- [ ] Change `listChanged: false` to `true` in initialize response
- [ ] Accept optional notification callback in routing context
- [ ] No changes to tools/list aggregation or tools/call dispatch logic

### Phase 5: Wire It Together

- [ ] Register circuit breaker callback → session registry broadcast
- [ ] Map backend URLs to profiles (reverse lookup from profile config)
- [ ] On circuit state change: determine affected profiles → broadcast

### Phase 6: Configuration (`gateway/config.py`)

- [ ] Add `session_ttl_seconds: float = 300.0` to gateway config
- [ ] Add `max_sessions_per_profile: int = 10` to gateway config

### Phase 7: Tests

- [ ] Session lifecycle tests (create, get, delete, TTL expiry)
- [ ] Circuit → notification broadcast integration test
- [ ] GET stream receives notification test
- [ ] Backwards compatibility: stateless POST still works
- [ ] Auth enforcement on GET/DELETE
- [ ] Max sessions enforcement

### Phase 8: Quality Gates

- [ ] `uv run ruff check src tests`
- [ ] `uv run mypy src`
- [ ] `uv run pytest -v`
- [ ] `gourmand --full .`
- [ ] `podman build -f Containerfile .`

---

## File Changes

### New Files

| File | Purpose |
|------|---------|
| `gateway/sessions.py` | Session registry with per-profile tracking, TTL, broadcast |
| `tests/test_gateway_sessions.py` | Session lifecycle and notification tests |

### Modified Files

| File | Changes |
|------|---------|
| `gateway/app.py` | Streamable HTTP handler: GET/DELETE support, session management |
| `gateway/router.py` | `listChanged: true`, notification callback plumbing |
| `gateway/circuit.py` | State change callback registration and invocation |
| `gateway/config.py` | Session TTL and max-sessions config fields |

---

## Testing Strategy

### Unit Tests
- [ ] `SessionRegistry` — create, get, delete, TTL, max sessions, broadcast
- [ ] `CircuitBreaker` — callback fires on state transitions
- [ ] Config validation — session TTL and max sessions defaults/overrides

### Integration Tests
- [ ] Full flow: POST initialize → session created → GET stream opened → circuit opens → notification received → tools/list returns updated set
- [ ] Backwards compat: POST without session ID → JSON response (no session created)
- [ ] Auth: GET/DELETE without bearer token → 401

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| FastMCP session manager API is internal/unstable | High | Pin FastMCP version; write thin adapter layer so we can swap later |
| 2026-07-28 spec removes sessions and GET streams | Medium | Build for current spec; adapter layer makes migration tractable |
| Session memory leak from abandoned sessions | Medium | TTL expiry + max sessions per profile |
| anyio task group constraints affect session lifecycle | High | Sessions manage transport references, not backend connections; backends stay fresh-per-call |

---

## Changelog

| Date | Changes |
|------|---------|
| 2026-07-02 | Initial plan |
