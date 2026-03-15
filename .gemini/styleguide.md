# CrunchTools MCP Server Code Review Standards

## Architecture
- Business logic belongs in `tools/*.py`, NOT in `server.py`
- `server.py` contains ONLY `@mcp.tool()` decorated functions that validate args and delegate
- MCP registration (`@mcp.tool()`) MUST NOT appear in `tools/*.py`
- HTTP calls go through `client.py` — tools never call `httpx` directly

## Security (Five-Layer Model)
- API credentials MUST use `SecretStr` — never logged, never in `repr()`
- Credentials MUST come from environment variables only — no hardcoded values
- No `eval()`, `exec()`, filesystem access, or shell execution
- Auth MUST go in headers, never in URLs
- URL path parameters MUST be encoded to prevent path traversal
- Pydantic models MUST use `extra="forbid"`

## Testing
- Every new tool MUST have a corresponding mocked test
- `test_tool_count` MUST be updated when tools are added or removed
- Tests use `httpx.AsyncClient` mocking — no live API calls
- Pydantic models need valid, invalid, and injection-prevention tests
- Security tests: token sanitization, ID truncation, config repr safety

## Naming
- PyPI package: `mcp-<name>-crunchtools`
- Python module: `mcp_<name>_crunchtools`
- CLI command: `mcp-<name>-crunchtools`

## Containerfile
- Use `Containerfile`, not `Dockerfile`
- Base on Hummingbird images (`quay.io/hummingbird/*`)
- Include OCI labels: `org.opencontainers.image.source`, `.description`, `.licenses`
- Always `dnf clean all` after installs

## Versioning
- Semantic Versioning 2.0.0 strictly
- AI-assisted commits MUST include `Co-Authored-By` trailer
- All code MUST pass gourmand checks before merge

## Distribution
- Every release MUST be available via uvx, pip, AND container
- All three MCP transports MUST work: stdio, SSE, streamable-http
