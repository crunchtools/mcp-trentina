# mcp-trentina-crunchtools

Secure MCP server for quarantined web content extraction — two-layer defense against prompt injection.

## Quick Start

```bash
uv sync --all-extras
uv run mcp-trentina-crunchtools
```

## Environment Variables

- `GEMINI_API_KEY` — Required for Layer 2 (Q-Agent)
- `QUARANTINE_MODEL` — Gemini model for Q-Agent (default: gemini-2.5-flash-lite)
- `QUARANTINE_SEARCH_MODEL` — Gemini model for L0 search grounding (default: gemini-2.5-flash; must support google_search)
- `QUARANTINE_FALLBACK` — "layer1" (default) or "fail"
- `QUARANTINE_MAX_CONTENT` — Max chars to Q-Agent (default: 100000)
- `QUARANTINE_DB` — SQLite blocklist path (default: ~/.local/share/mcp-trentina/trentina.db)
- `QUARANTINE_TRUST_CONFIG` — Trust allowlist JSON path

## Tools (6)

### Safe (Layer 1 only)
- safe_fetch, safe_read

### Quarantine (Layer 1 + Layer 2)
- quarantine_fetch, quarantine_read, quarantine_scan

### Stats
- quarantine_stats

## Development

```bash
uv run ruff check src tests    # Lint
uv run mypy src                # Type check
uv run pytest -v               # Test
podman run --rm -v .:/repo:Z quay.io/crunchtools/gourmand:latest --full /repo  # Slop detection
podman build -f Containerfile . # Container
```

## Architecture

- `sanitize/` — Layer 1: 7-stage deterministic sanitization pipeline
- `quarantine/` — Layer 2: Q-Agent (Gemini REST via httpx, NO SDK, NO tools)
- `tools/` — Tool implementations called by server.py wrappers
- `database.py` — SQLite blocklist for cumulative detection memory
- `gateway/` — Per-consumer MCP gateway proxy with tool allowlists, parameter guards, and defense pipeline
  - **Parameter guards**: per-tool argument validation with allow/deny value patterns — see `docs/gateway-design.md`
