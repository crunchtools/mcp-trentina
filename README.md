# mcp-trentina-crunchtools

<!-- mcp-name: io.github.crunchtools/trentina -->

Secure MCP server for quarantined web content extraction with two-layer prompt injection defense.

## Tools (6)

| Tool | Layers | Description |
|------|--------|-------------|
| `safe_fetch` | L1 | Fetch URL, sanitize, return markdown. Fails on injection. |
| `safe_read` | L1 | Read local file, sanitize, return markdown. Fails on injection. |
| `quarantine_fetch` | L1+L2 | Fetch URL, sanitize, extract via Q-Agent. Warns on injection. |
| `quarantine_read` | L1+L2 | Read local file, sanitize, extract via Q-Agent. Warns on injection. |
| `quarantine_scan` | L1+L2 | Pre-flight scan: detect injection vectors WITHOUT returning content. |
| `quarantine_stats` | — | Session stats, config, and blocklist summary. |

## Architecture

- **Layer 1 (Deterministic):** 7-stage sanitization pipeline strips hidden HTML, invisible unicode, encoded payloads, exfiltration URLs, and LLM delimiters.
- **Layer 2 (Q-Agent):** Quarantined Gemini Flash-Lite LLM for semantic content extraction — NO tools, NO memory, NO SDK.

## Install

```bash
# PyPI
pip install mcp-trentina-crunchtools

# uvx (zero-install)
uvx mcp-trentina-crunchtools

# Container
podman run quay.io/crunchtools/mcp-trentina
```

## Configuration

```bash
# Required for Layer 2 (Q-Agent)
export GEMINI_API_KEY=your-key

# Optional
export QUARANTINE_MODEL=gemini-2.0-flash-lite  # default
export QUARANTINE_FALLBACK=layer1              # or "fail"
export QUARANTINE_MAX_CONTENT=100000           # max chars to Q-Agent
export QUARANTINE_DB=/data/trentina.db          # SQLite blocklist path
export QUARANTINE_TRUST_CONFIG=~/.config/mcp-env/mcp-trentina-trust.json
```

## Claude Code

```json
{
  "mcpServers": {
    "mcp-trentina-crunchtools": {
      "command": "uvx",
      "args": ["mcp-trentina-crunchtools"]
    }
  }
}
```

## License

AGPL-3.0-or-later
