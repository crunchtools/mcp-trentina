# mcp-airlock-crunchtools

Secure MCP server for quarantined web content extraction — three-layer defense against prompt injection.

## Quick Start

```bash
uv sync --all-extras
uv run mcp-airlock-crunchtools
```

## Environment Variables

- `GEMINI_API_KEY` — Required for Layer 3 (Q-Agent)
- `QUARANTINE_MODEL` — Gemini model (default: gemini-2.5-flash-lite)
- `QUARANTINE_FALLBACK` — "layer1" (default) or "fail"
- `QUARANTINE_MAX_CONTENT` — Max chars to Q-Agent (default: 100000)
- `QUARANTINE_DB` — SQLite path (default: ~/.local/share/mcp-airlock/airlock.db)
- `QUARANTINE_TRUST_CONFIG` — Trust seed JSON path (one-time import to SQLite)

## Tools (6)

| Tool | Purpose |
|------|---------|
| `fetch(url, prompt)` | Fetch URL through L1→L2→L3 pipeline. Returns content + detection metadata. |
| `read(path, prompt)` | Read file through L1→L2→L3 pipeline. Returns content + detection metadata. |
| `search(query, prompt, num_results)` | Search web via L0→L1→L2→L3. Returns results + detection metadata. |
| `scan(url, path, content, content_type)` | Pre-flight threat assessment. Returns risk level only, no content. |
| `blocklist(source)` | P-Agent-initiated blocking. Adds source to SQLite blocklist. |
| `stats()` | Pipeline config, layer status, blocklist summary. |

All tools run the full defense pipeline and return detection metadata. The P-Agent evaluates detection metadata and decides whether to blocklist sources.

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
- `quarantine/` — Layer 2 (Prompt Guard 2 classifier) + Layer 3 (Q-Agent: Gemini REST via httpx, NO SDK, NO tools)
- `tools/` — Tool implementations: fetch, read, search, scan, blocklist, stats
- `database.py` — SQLite: blocklist, events, trusted domains
- `dbus_interface.py` — D-Bus interface for Cockpit (trust management, events, stats)
