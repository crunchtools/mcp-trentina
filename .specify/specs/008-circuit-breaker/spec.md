# Specification: Backend Circuit Breaker

> **Spec ID:** 008-circuit-breaker
> **Status:** Draft
> **Version:** 0.1.0
> **Author:** Scott McCarty
> **Date:** 2026-06-28

## Overview

Trentina is critical infrastructure — every Claude Code session, every agent (Kagetora, Takeda), and every LLM proxy request flows through it. A single unreachable backend MCP server currently blocks the entire `tools/list` response, taking down all profiles that reference that backend. This spec adds a circuit breaker to the gateway backend layer so that backend failures are isolated, fast, and self-healing.

---

## Problem Analysis

### Root Cause

`_route_tools_list` in `router.py` iterates backends **sequentially** with a `for` loop. Each backend call wraps `_do_list_tools` in `asyncio.wait_for(timeout=backend.timeout_seconds)`. The default timeout is **30 seconds**. A profile with 12 backends and 1 dead backend blocks `tools/list` for up to 30 seconds before skipping the dead one and proceeding — which exceeds Claude Code's MCP connection timeout.

### Failure Cascade

```
Dead backend (e.g. rotv, 30s timeout)
    → tools/list blocks for 30s
    → Claude Code MCP connection times out (~20s)
    → Client reconnects, hits tools/list again
    → Same 30s block, same timeout
    → Gateway appears completely dead
```

### All Failure Surfaces (audit)

| Surface | Current Behavior | Risk |
|---------|-----------------|------|
| `tools/list` — sequential backend iteration | 30s timeout per dead backend, blocks entire response | **Critical** — the #36 bug |
| `tools/list` — `maybe_trigger_compression()` | Calls `list_backend_tools` for each compressible backend; same sequential + 30s timeout | **High** — compression of a dead backend blocks startup |
| `tools/call` — single backend call | 30s timeout, returns JSON-RPC error | **Medium** — affects only one call, client retries |
| LLM proxy — upstream timeout | 300s read timeout (appropriate for streaming LLM), returns 504 | **Low** — per-request, no cascade |
| Matrix proxy — upstream timeout | 120s read timeout (appropriate for /sync long-poll), returns 504 | **Low** — per-request, no cascade |
| Compression — Gemini timeout | 60s timeout with retries, logged and skipped | **Low** — best-effort by design |

---

## Solution: Three-Part Fix

### Part 1: Parallel Backend Fetching in tools/list

Replace the sequential `for` loop in `_route_tools_list` with `asyncio.gather` so all backends are queried concurrently. A dead backend's timeout no longer blocks healthy backends.

**Before:** Wall-clock = sum of all backend timeouts
**After:** Wall-clock = max of all backend timeouts (in practice, the healthy ones return in <1s)

### Part 2: Circuit Breaker on Backend Connections

Add a circuit breaker to `backend.py` that tracks consecutive failures per backend URL. After N consecutive failures (default: 3), the circuit opens and immediately rejects calls for a cooldown period (default: 60 seconds) without attempting the connection.

States:
- **Closed** (normal): calls pass through to the backend
- **Open** (tripped): calls fail immediately with `BackendCallError("circuit open")`
- **Half-open** (probing): after cooldown expires, one call is allowed through to test recovery

This prevents the gateway from spending timeout-seconds on every single request to a known-dead backend.

### Part 3: Short Timeout for tools/list

Add a separate, shorter timeout for `list_backend_tools` (default: 10 seconds) distinct from `call_backend_tool`'s operational timeout (remains at `backend.timeout_seconds`, default 30s). Tool listing is a lightweight metadata operation — if a backend can't respond in 10 seconds, it's effectively down.

---

## No New Tools

This change is internal to the gateway. No new MCP tools are added.

---

## Security Considerations

### Layer 1 — Token Protection
- No change. Circuit breaker state is in-memory, not persisted.

### Layer 2 — Input Validation
- No change. Circuit breaker parameters use existing Pydantic validation on `Backend` model.

### Layer 3 — API Hardening
- **Improved.** Shorter list timeout and circuit breaker reduce the window for connection-level DoS against the gateway.

### Layer 4 — Dangerous Operation Prevention
- No change. No new filesystem or shell access.

### Security Note
- Circuit breaker state is **not** controllable by consumers. A consumer cannot force a circuit open or closed — state transitions are driven entirely by backend response behavior observed by the gateway.

---

## Module Changes

### New Files

| File | Purpose |
|------|---------|
| `gateway/circuit.py` | Circuit breaker implementation |

### Modified Files

| File | Changes |
|------|---------|
| `gateway/backend.py` | Integrate circuit breaker checks before backend calls |
| `gateway/router.py` | Replace sequential loop with `asyncio.gather` in `_route_tools_list` |
| `gateway/profile.py` | Add `list_timeout_seconds` field to `Backend` model |
| `gateway/__init__.py` | Export circuit breaker if needed for stats |

---

## Testing Requirements

### Mocked Tests

- [ ] `test_circuit_breaker.py` — unit tests for circuit state machine
  - Closed → stays closed on success
  - Closed → opens after N consecutive failures
  - Open → rejects immediately (no backend call)
  - Open → transitions to half-open after cooldown
  - Half-open → closes on success
  - Half-open → re-opens on failure
  - Concurrent calls during half-open: only one probe allowed
- [ ] `test_gateway_router.py` — new tests
  - tools/list with parallel fetch (multiple backends, verify all returned)
  - tools/list with one dead backend (verify others still returned promptly)
  - tools/list with circuit-open backend (verify immediate skip, no timeout)
- [ ] `test_gateway_backend.py` — new tests
  - list_backend_tools respects `list_timeout_seconds`
  - Circuit breaker integration (failure count tracking)

### Input Validation Tests
- [ ] `list_timeout_seconds` Pydantic validation (positive, <= 60s)

### Tool Count Update
- [ ] No change — no new tools

---

## Configuration

### Backend Model Additions

```yaml
backends:
  rotv:
    url: http://mcp-rotv:8080/mcp
    timeout_seconds: 30        # operational call timeout (existing)
    list_timeout_seconds: 10   # tools/list timeout (new, default 10)
```

### Circuit Breaker Defaults (not configurable per-backend in v1)

| Parameter | Default | Rationale |
|-----------|---------|-----------|
| `failure_threshold` | 3 | Open after 3 consecutive failures |
| `cooldown_seconds` | 60 | Wait 60s before probing |
| `half_open_max_probes` | 1 | Only 1 concurrent probe in half-open |

---

## Dependencies

- Depends on: None
- Blocks: None

---

## Open Questions

1. Should circuit breaker state be observable via `quarantine_stats` or a new gateway health endpoint? (Defer to #14, Cockpit rewrite.)
2. Should circuit breaker parameters be configurable per-backend in YAML? (Not in v1 — keep it simple, add if needed.)

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | 2026-06-28 | Initial draft |
