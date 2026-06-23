# Specification: Content-Based Tools for MCP-to-MCP Integration

> **Spec ID:** 004-content-tools
> **Status:** Draft
> **Version:** 0.2.0
> **Author:** Scott McCarty / Josui
> **Date:** 2026-03-10
> **GitHub Issue:** [#5](https://github.com/crunchtools/mcp-trentina/issues/5)

## Overview

Airlock's existing tools require the content source to be either a URL (fetch tools)
or a file path inside the container (read tools). This creates a hard dependency on
filesystem access or web availability — neither of which exists when another MCP agent
needs to pass content through airlock's defense pipeline.

Takeda (OpenClaw Signal bot on lotor) is the immediate consumer. It receives Signal
messages containing URLs, pasted text, and decoded attachments. It connects to airlock
over streamable-http on the same host but cannot mount volumes into the airlock
container or serve content via HTTP for airlock to fetch.

Content tools solve this by accepting raw text as an MCP tool parameter. The content
enters the same three-layer pipeline (L1 deterministic, L2 classifier, L3 Q-Agent) as
URL and file content. No filesystem, no HTTP fetch — just a string in, sanitized
result out.

---

## Architecture

### Four New Tools

| Tool | Purpose |
|------|---------|
| `safe_content` | Sanitize inline content. Block and blocklist if injection detected. |
| `quarantine_content` | Sanitize + Q-Agent extraction. Warn but proceed on injection. |
| `scan_content` | Threat assessment only. L2/L3 analyze sanitized content. |
| `deep_scan_content` | Threat assessment only. L1 runs for stats, L2/L3 analyze raw content. |

These mirror the existing tool pairs exactly:

| Content Source | Safe | Quarantine | Scan | Deep Scan |
|---------------|------|------------|------|-----------|
| URL | `safe_fetch` | `quarantine_fetch` | `quarantine_scan(url=)` | `deep_quarantine_scan(url=)` |
| File | `safe_read` | `quarantine_read` | `quarantine_scan(path=)` | `deep_quarantine_scan(path=)` |
| Inline | `safe_content` | `quarantine_content` | `scan_content` | `deep_scan_content` |

### Tool Interfaces

```python
async def safe_content(content: str, content_type: str = "text/plain") -> dict[str, Any]:
    """Sanitize inline content. Fails if injection detected."""

async def quarantine_content(
    content: str,
    prompt: str = "Extract the main content.",
    content_type: str = "text/plain",
) -> dict[str, Any]:
    """Sanitize + Q-Agent extraction on inline content."""

async def scan_content(content: str, content_type: str = "text/plain") -> dict[str, Any]:
    """Three-layer scan on inline content. L2/L3 see sanitized output."""

async def deep_scan_content(content: str, content_type: str = "text/plain") -> dict[str, Any]:
    """Three-layer deep scan. L1 runs for stats, L2/L3 see raw content."""
```

### Pipeline Selection via content_type

The `content_type` parameter replaces the `looks_like_html()` heuristic used by
fetch and read tools. The caller knows what it's sending — no need to guess.

| content_type | Pipeline | Notes |
|-------------|----------|-------|
| `text/html` | Full 7-stage HTML sanitization | BeautifulSoup → markdownify → unicode → encoded → exfil → delimiters → directives |
| `text/plain` | Text-only 5-stage pipeline | unicode → encoded → exfil → delimiters → directives |
| `text/markdown` | Text-only 5-stage pipeline | Same as text/plain — markdown is plain text with formatting |

Default: `text/plain`. As a safety fallback, if `content_type` is `text/plain` but
the content starts with `<!DOCTYPE` or `<html`, upgrade to the HTML pipeline
automatically. This prevents an attacker from sending HTML with a misleading
content_type to bypass HTML-specific sanitization.

### Trust Model

Inline content is **always untrusted**. URL tools have trusted domains. File tools
have trusted paths. Content tools have no source to match against — there is no
trust allowlist for raw strings. All three layers always run on every request.

This means `safe_content` always runs L1 + L2 + L3 detection (not just L1 like
`safe_fetch` does for trusted domains). The cost is higher per-call, but the
security posture is correct — you don't know where this string came from.

### Blocklist via Content Hash

URL and file tools use the source URL or path as the blocklist key. Inline content
has no stable identifier, so the blocklist uses a SHA-256 hash of the content.

```python
content_hash = f"sha256:{hashlib.sha256(content.encode('utf-8')).hexdigest()}"
```

This is deterministic — identical content always produces the same hash. If airlock
detects injection in a piece of content and blocklists it, submitting the same content
again will be blocked immediately without re-running the pipeline.

Blocklist operations use the existing `is_blocked()` and `record_detection()` functions
with `source_type="content"` and `source=content_hash`.

### Content Size Limit

All content tools reject content exceeding `QUARANTINE_MAX_CONTENT` (default 100,000
chars) **before any processing**. This is a hard reject, not a truncation — the caller
gets a clear error. Truncating silently would mean the tail of the content (which might
contain the injection) is never analyzed.

---

## Pipeline Behavior by Tool

Each tool follows the same pattern as its URL/file counterpart:

| Tool | L1 | L2 (classify) | L3 (Q-Agent) | On Injection |
|------|----|----|----|----|
| `safe_content` | Sanitize | Classify sanitized | Detect on sanitized | Block + blocklist |
| `quarantine_content` | Sanitize | Classify sanitized | Extract from sanitized | Warn + return extracted content |
| `scan_content` | Sanitize (for stats + clean text) | Classify sanitized | Detect on sanitized | Report risk level |
| `deep_scan_content` | Sanitize (for stats only) | Classify raw | Detect on raw | Report risk level |

### Standard vs Deep Scan

The standard/deep distinction applies to content tools the same way it applies to
URL and file scans:

- **Standard (`scan_content`)**: L1 sanitizes the content. L2 and L3 analyze the
  sanitized output. Useful for seeing what survives stripping.
- **Deep (`deep_scan_content`)**: L1 runs for stats reporting only. L2 and L3
  analyze the raw input. Higher risk of Q-Agent compromise but catches injection
  vectors that L1 would strip before L2/L3 could evaluate them.

The content source (URL, file, parameter) is irrelevant to this distinction. The
question is whether the classifier and Q-Agent see pre-stripped or raw text.

---

## Response Shape

Content tools return the same structure as URL/file tools, with `content_hash` instead
of `source_url` or `source_path`:

**safe_content response:**
```json
{
  "content": "sanitized text...",
  "trust": {
    "level": "sanitized-only",
    "source": "layer1",
    "content_hash": "sha256:abc123..."
  },
  "sanitization": {
    "input_size": 4500,
    "output_size": 3200,
    "stripped": { "html_hidden_elements": 0, "delimiters_llm_delimiters": 2, ... }
  }
}
```

**scan_content response:**
```json
{
  "source_type": "content",
  "source": "sha256:abc123...",
  "scan_mode": "standard",
  "risk_level": "low",
  "layer1": { "detections": 0, "risk_level": "low", "stats": {...} },
  "layer2": { "available": true, "result": { "label": "BENIGN", "score": 0.01 }, "risk_level": "low" },
  "qagent": { "available": true, "assessment": {...}, "risk_level": "low" },
  "recommendation": "Source appears clean. Safe to use safe_content."
}
```

---

## Security Considerations

### No Filesystem Access
Content exists only in memory during processing. It is never written to disk. The
blocklist stores only the SHA-256 hash and detection metadata — not the content
itself. A compromised blocklist database reveals hashes, not payloads.

### No New Credentials
Content tools use the same Gemini API key as existing tools. No new secrets, no new
outbound connections.

### Content-Type Bypass Prevention
An attacker could send HTML with `content_type="text/plain"` to bypass HTML-specific
stripping (hidden divs, comments, etc.). The safety fallback — auto-upgrading to the
HTML pipeline when content starts with `<!DOCTYPE` or `<html` — mitigates this. It
doesn't catch all HTML (a bare `<div>` without doctype would slip through), but it
catches the common case.

### MCP Transport Security
Content tools accept potentially large strings over the MCP protocol. The
`QUARANTINE_MAX_CONTENT` size limit prevents memory exhaustion. The MCP framework
(FastMCP/uvicorn) has its own request size limits that provide an additional layer
of protection.

---

## Module Changes

### New Files

| File | Purpose |
|------|---------|
| `tools/content.py` | Four async functions: `safe_content`, `quarantine_content`, `scan_content`, `deep_scan_content` |
| `tests/test_content.py` | Mocked tests for all four content tools |

### Modified Files

| File | Changes |
|------|---------|
| `tools/__init__.py` | Add four new exports |
| `server.py` | Add four `@mcp.tool()` wrappers |

### Unchanged Files

`database.py`, `config.py`, `sanitize/`, `quarantine/` — all unchanged. Content tools
use the existing pipeline functions, classifier, Q-Agent, and database exactly as-is.
The only new code is the tool orchestration layer in `content.py`.

---

## Testing Requirements

### Content Tool Tests (`test_content.py`)

**safe_content:**
- `test_safe_content_clean` — clean text/plain passes through unchanged
- `test_safe_content_html` — text/html content gets full HTML pipeline
- `test_safe_content_blocks_injection` — classifier MALICIOUS triggers BlockedSourceError
- `test_safe_content_size_limit` — content exceeding max rejected before processing
- `test_safe_content_auto_upgrades_html` — text/plain with `<!DOCTYPE` triggers HTML pipeline

**quarantine_content:**
- `test_quarantine_content_extracts` — Q-Agent extraction returns structured content
- `test_quarantine_content_warns_on_injection` — classifier warning added, content still returned

**scan_content / deep_scan_content:**
- `test_scan_content_clean` — clean content returns low risk across all layers
- `test_scan_content_malicious` — injection returns high/critical risk
- `test_deep_scan_passes_raw_to_classifier` — deep mode sends raw content to L2
- `test_scan_passes_sanitized_to_classifier` — standard mode sends sanitized content to L2

**Blocklist:**
- `test_blocklist_uses_content_hash` — detection records hash, second submission blocked

**Tool registration:**
- Update `test_tool_count` from 7 to 11
- Update `test_expected_tools_registered` with four new tool names

---

## Dependencies

- Depends on: None. All required infrastructure (pipeline, classifier, Q-Agent, database) exists.
- Blocks: Takeda/OpenClaw airlock integration on lotor.

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | 2026-03-10 | Initial draft |
| 0.2.0 | 2026-03-10 | Rewritten as engineering spec. Added architecture rationale, pipeline behavior table, content-type bypass analysis, response shape examples, standard vs deep scan explanation. |
