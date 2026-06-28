# Implementation Plan: Backend Circuit Breaker

> **Spec ID:** 008-circuit-breaker
> **Status:** Planning
> **Last Updated:** 2026-06-28

## Summary

Three-part fix: (1) parallelize `tools/list` backend fetching with `asyncio.gather`, (2) add a circuit breaker to `backend.py` that tracks failures per-URL and short-circuits known-dead backends, (3) add a separate shorter timeout for tool listing vs operational calls.

---

## Architecture

### Failure Flow (current)

```
tools/list request
    │
    ├── backend-1 (healthy) ── 200ms ──┐
    ├── backend-2 (dead)    ── 30s  ──┤  sequential
    ├── backend-3 (healthy) ── 150ms ──┤  total = sum
    └── ...                            │
                                       ▼
                              response (30.35s)
```

### Failure Flow (after)

```
tools/list request
    │
    ├── backend-1 (healthy) ── 200ms ──┐
    ├── backend-2 (circuit open) ── 0ms ──┤  parallel
    ├── backend-3 (healthy) ── 150ms ──┤  total = max
    └── ...                            │
                                       ▼
                              response (200ms)
```

### Circuit Breaker State Machine

```
         success
    ┌──────────────┐
    │              │
    ▼              │
 CLOSED ──N fails──> OPEN ──cooldown──> HALF_OPEN
    ▲                  ▲                   │
    │                  │                   │
    │                  └───── fail ────────┘
    │                                      │
    └──────────── success ─────────────────┘
```

---

## Implementation Steps

### Phase 1: Circuit Breaker Module

- [ ] Create `gateway/circuit.py` with `CircuitBreaker` class
  - Per-URL state tracking (dict keyed by URL)
  - Thread-safe via asyncio (single event loop, no locks needed)
  - `check(url)` — returns True if call allowed, False if circuit open
  - `record_success(url)` — reset failure count, close circuit
  - `record_failure(url)` — increment count, open if threshold reached
  - Uses `time.monotonic()` for cooldown timing (immune to clock skew)

### Phase 2: Backend Integration

- [ ] Add `list_timeout_seconds` field to `Backend` model in `profile.py`
  - Default: 10.0, gt=0, le=60.0
- [ ] Modify `list_backend_tools` in `backend.py` to:
  - Check circuit breaker before attempting connection
  - Use `list_timeout_seconds` instead of `timeout_seconds`
  - Record success/failure to circuit breaker
- [ ] Modify `call_backend_tool` to record success/failure to circuit breaker

### Phase 3: Parallel tools/list

- [ ] Rewrite `_route_tools_list` in `router.py`:
  - Create async tasks for all backends
  - Use `asyncio.gather(*tasks, return_exceptions=True)`
  - Collect results, skip exceptions (same as current `continue` behavior)
  - Log skipped backends with reason (timeout, circuit open, other error)

### Phase 4: Tests

- [ ] `tests/test_circuit_breaker.py` — state machine unit tests
- [ ] Update `tests/test_gateway_router.py` — parallel fetch tests
- [ ] Update `tests/test_gateway_backend.py` if it exists, or add backend-level tests

### Phase 5: Quality Gates

- [ ] `uv run ruff check src tests`
- [ ] `uv run mypy src`
- [ ] `uv run pytest -v`
- [ ] `gourmand --full .` (if available)
- [ ] `podman build -f Containerfile .`

---

## File Changes

### New Files

| File | Purpose |
|------|---------|
| `gateway/circuit.py` | Circuit breaker state machine |
| `tests/test_circuit_breaker.py` | Circuit breaker unit tests |

### Modified Files

| File | Changes |
|------|---------|
| `gateway/profile.py` | Add `list_timeout_seconds` to `Backend` |
| `gateway/backend.py` | Circuit breaker checks + list timeout |
| `gateway/router.py` | `asyncio.gather` in `_route_tools_list` |
| `gateway/__init__.py` | Export circuit breaker module |

---

## Testing Strategy

### Unit Tests (circuit.py)

- State transitions: closed → open → half-open → closed
- Failure threshold boundary (2 failures = still closed, 3 = open)
- Cooldown expiry (mock time.monotonic)
- Half-open probe semantics (one allowed, rest rejected)
- Independent circuits per URL

### Integration Tests (router.py)

- Parallel fetch returns tools from all healthy backends
- Dead backend skipped, healthy backends unaffected
- Circuit-open backend returns immediately (no wait)
- Mixed internal + external backends with one dead

### Regression Tests

- Existing `test_tools_list_skips_unreachable_backend` still passes
- Existing `test_tools_list_aggregates_and_namespaces` still passes

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Circuit stays open after backend recovers | Med | 60s cooldown + half-open probe ensures recovery within ~1 min |
| `asyncio.gather` changes tool ordering | Low | Tool order was never guaranteed; clients don't depend on it |
| Race condition in circuit state | Low | Single event loop, no threads; `time.monotonic` is monotonic |
| Backend flaps (up-down-up rapidly) | Low | 3-failure threshold prevents premature opens; success resets immediately |

---

## Changelog

| Date | Changes |
|------|---------|
| 2026-06-28 | Initial plan |
