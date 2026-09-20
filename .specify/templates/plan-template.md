# Implementation Plan: [Feature Name]

> **Spec ID:** XXX-feature-name
> **Status:** Planning | In Progress | Complete
> **Last Updated:** YYYY-MM-DD

## Summary

[1-2 sentence summary of implementation approach]

---

## Architecture

### Tool Flow

```
Claude Code / AI Client
    │
    ▼
server.py (@mcp.tool)
    │ validates args
    ▼
tools/group.py (async function)
    │ builds params/json
    ▼
client.py (httpx request)
    │ handles errors, pagination
    ▼
GitLab REST API v4
```

### Data Flow

1. [Step 1]
2. [Step 2]
3. [Step 3]

---

## Implementation Steps

### Phase 1: Tool Functions

- [ ] Create `tools/new_group.py` with async functions
- [ ] Add exports to `tools/__init__.py`
- [ ] Add `__all__` entries

### Phase 2: Server Registration

- [ ] Import tools in `server.py`
- [ ] Add `@mcp.tool()` wrappers with docstrings

### Phase 3: Input Validation (if needed)

- [ ] Add Pydantic models to `models.py`
- [ ] Add constants for field limits

### Phase 4: Tests

- [ ] Add mocked API tests in `test_tools.py`
- [ ] Add validation tests in `test_validation.py`
- [ ] Update tool count assertion

### Phase 5: Quality Gates

- [ ] `uv run ruff check src tests`
- [ ] `uv run mypy src`
- [ ] `uv run pytest -v`
- [ ] `gourmand --full .`
- [ ] Push the branch — GHA builds the container (`.github/workflows/container.yml`)

---

## File Changes

### New Files

| File | Purpose |
|------|---------|
| `tools/new_group.py` | [Description] |

### Modified Files

| File | Changes |
|------|---------|
| `tools/__init__.py` | Add imports and `__all__` entries |
| `server.py` | Add `@mcp.tool()` wrappers |
| `tests/test_tools.py` | Add test class, update tool count |

---

## Testing Strategy

### Mocked Tests

- [ ] `test_list_*` — verify list response with pagination headers
- [ ] `test_get_*` — verify single resource response
- [ ] `test_create_*` — verify POST with 201 response
- [ ] `test_update_*` — verify PUT response
- [ ] `test_delete_*` — verify 204 No Content handling

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| [Risk 1] | [High/Med/Low] | [How to mitigate] |

---

## Changelog

| Date | Changes |
|------|---------|
| YYYY-MM-DD | Initial plan |
