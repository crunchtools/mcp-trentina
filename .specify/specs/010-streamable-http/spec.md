# Specification: Streamable HTTP Transport for Gateway

> **Spec ID:** 010-streamable-http
> **Status:** Draft
> **Version:** 0.1.0
> **Author:** Scott McCarty
> **Date:** 2026-07-02

## Overview

Upgrades the gateway endpoint from stateless POST-only HTTP to the MCP Streamable
HTTP transport (spec 2025-03-26). This enables session persistence and
server-initiated notifications — specifically `notifications/tools/listChanged`
when circuit breaker state changes. Agents currently hold stale tool lists when
backends die or recover; with Streamable HTTP, the gateway can push a notification
that triggers agents to re-request `tools/list`.

FastMCP 2.14.4 already has production-ready Streamable HTTP support via
`StreamableHTTPSessionManager`. The work is bridging Trentina's custom proxy logic
(profile auth, tool namespacing, allowlists, parameter guards, circuit breaker,
defense pipeline) with FastMCP's session management.

---

## Endpoint Changes

| Endpoint | Method | Phase 1 (current) | Phase 2 (this spec) |
|---|---|---|---|
| `/gateway/{profile}/mcp` | POST | JSON-RPC request → JSON response | JSON-RPC request → JSON or SSE response (server chooses per-request) |
| `/gateway/{profile}/mcp` | GET | 405 | SSE stream for server-push notifications (`tools/listChanged`) |
| `/gateway/{profile}/mcp` | DELETE | 405 | Tear down session, free resources |

The endpoint path stays the same. Existing stateless POST clients continue to work —
the server can return plain JSON for simple request/response cycles. SSE streaming
is used when the server needs to interleave notifications.

---

## Session Management

### Session Lifecycle

1. Client POSTs `initialize` request (no `Mcp-Session-Id` header)
2. Gateway creates session via `StreamableHTTPSessionManager`, returns `Mcp-Session-Id` header
3. Client includes `Mcp-Session-Id` on all subsequent requests
4. Client MAY open GET to receive server-push notifications
5. Client sends DELETE to tear down session (or session expires via TTL)

### Session State

Each session tracks:
- **Session ID** — UUIDv4, assigned by `StreamableHTTPSessionManager`
- **Profile** — which consumer profile owns this session
- **Active GET streams** — for pushing notifications
- **Created/last-access timestamps** — for TTL expiry

### Session TTL

Sessions expire after inactivity (default: 5 minutes). Expired sessions return
HTTP 404, prompting the client to re-initialize.

---

## Notification: tools/listChanged

### Trigger Conditions

The gateway emits `notifications/tools/listChanged` when the effective tool list
for a profile changes:

1. **Circuit opens** — a backend's tools become unavailable
2. **Circuit closes** — a backend's tools become available again
3. **Circuit half-open probe succeeds** — backend recovered, tools restored

### Broadcast Mechanism

Circuit breaker state changes are broadcast to all active sessions for affected
profiles:

1. `circuit.py` detects state transition (CLOSED→OPEN, HALF_OPEN→CLOSED, etc.)
2. Calls notification callback registered by the session layer
3. Session layer iterates `session_manager._server_instances` for matching profiles
4. Sends `{"jsonrpc": "2.0", "method": "notifications/tools/listChanged"}` via
   each transport's write stream

### Agent Behavior

On receiving `tools/listChanged`, a well-behaved MCP client (Claude Code, etc.)
re-requests `tools/list`. The gateway returns the current tool set — with
circuit-blocked backends' tools excluded.

---

## Security Considerations

### Layer 1 — Token Protection
- No new tokens. Bearer token auth continues per-request (including GET/DELETE).
- Session IDs are opaque UUIDs, not bearer tokens — they identify sessions, not
  authorize them. Every request still requires the profile's bearer token.

### Layer 2 — Input Validation
- GET requests validated: must include valid `Mcp-Session-Id` header
- DELETE requests validated: must include valid `Mcp-Session-Id` header
- Session IDs validated against `SESSION_ID_PATTERN` (visible ASCII only)

### Layer 3 — API Hardening
- Session TTL prevents resource exhaustion from abandoned sessions
- Maximum concurrent sessions per profile (configurable, default: 10)

### Layer 4 — Dangerous Operation Prevention
- No new shell/eval/file-write paths
- Notifications are read-only signals (no parameters, no data exfiltration risk)

---

## Module Changes

### Modified Files

| File | Changes |
|------|---------|
| `gateway/app.py` | Replace custom Starlette POST handler with Streamable HTTP session integration; enable GET/DELETE; add session tracking and notification broadcast |
| `gateway/router.py` | Change `listChanged: false` to `true` in initialize response; accept notification callback; support SSE streaming on POST responses |
| `gateway/circuit.py` | Add callback hook for state transitions; emit notification on CLOSED→OPEN, HALF_OPEN→CLOSED, OPEN→HALF_OPEN |
| `gateway/config.py` | Add session TTL and max-sessions-per-profile to gateway config |

### New Files

| File | Purpose |
|------|---------|
| `gateway/sessions.py` | Session registry: tracks active sessions per profile, handles broadcast, TTL expiry |

### Unchanged Files

| File | Why |
|------|-----|
| `gateway/auth.py` | Bearer token validation works per-request, no change needed |
| `gateway/backend.py` | Backend connections stay fresh-per-call (anyio constraint) |
| `gateway/guards.py` | Parameter guard validation timing unchanged |
| `gateway/internal.py` | Internal backend dispatch unchanged |
| `gateway/filter.py` | Tool filtering logic unchanged |
| `server.py` | FastMCP tool registration unchanged |
| `tools/*.py` | Defense pipeline unchanged |

---

## Testing Requirements

### Mocked Tests
- [ ] Session lifecycle: initialize → session ID returned → subsequent requests include session ID → DELETE tears down
- [ ] GET stream: client opens GET with session ID → receives SSE stream → notification pushed
- [ ] Circuit notification: circuit opens → `tools/listChanged` emitted → circuit closes → `tools/listChanged` emitted
- [ ] Session TTL: expired session returns 404
- [ ] Auth on GET/DELETE: missing/invalid bearer token returns 401
- [ ] Backwards compatibility: stateless POST without session ID still works (JSON response)
- [ ] Max sessions: exceeding limit returns appropriate error

### Tool Count Update
- [ ] No tool count change (no new tools added)

---

## Dependencies

- Depends on: 006-gateway-mode (current gateway architecture), 008-circuit-breaker (merged)
- Blocks: #44 (emit listChanged notification when circuit breaker opens/closes)

---

## Open Questions

1. **Upcoming spec change (2026-07-28 RC):** The next MCP spec revision removes GET streams and session IDs entirely. Should we build for the current spec (2025-03-26) knowing it may change, or wait? **Decision:** Build for current spec — Claude Code speaks it today, and the RC isn't shipped yet. We can adapt later.

2. **Per-profile session limits:** What's the right default? 10 concurrent sessions per profile seems reasonable for a personal gateway. Could be configurable.

3. **Notification scope:** Should `tools/listChanged` only go to sessions whose profile includes the affected backend, or broadcast to all sessions? **Decision:** Only affected profiles — no point notifying a profile that doesn't use the dead backend.

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | 2026-07-02 | Initial draft |
