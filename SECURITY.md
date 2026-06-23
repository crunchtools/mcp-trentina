# Security Design Document

This document describes the security architecture of mcp-trentina-crunchtools.

## 1. Threat Model

### 1.1 Assets to Protect

| Asset | Sensitivity | Impact if Compromised |
|-------|-------------|----------------------|
| Consuming agent's tool-calling capabilities | Critical | Attacker uses agent to send emails, modify files, call APIs |
| API credentials (Gemini, connected systems) | Critical | Data theft, unauthorized access |
| Data in connected systems | High | Exfiltration, modification, deletion |
| SQLite blocklist database | Low | Detection history exposed |

### 1.2 Threat Actors

| Actor | Capability | Motivation |
|-------|------------|------------|
| Malicious website operator | Plants injection in page content | Tool hijacking, data exfiltration |
| Compromised legitimate site | XSS injects prompt injection | Lateral movement via trusted domain |
| Malicious project contributor | Injection in README, comments, CI | Privilege escalation via code review |
| SEO poisoning | Injection in search results | Agent manipulation |

### 1.3 Attack Vectors

| Vector | Description | Mitigation |
|--------|-------------|------------|
| **Hidden HTML injection** | display:none, off-screen, same-color text | Layer 1 strips hidden elements |
| **Invisible unicode** | Zero-width chars, bidi overrides | Layer 1 strips + NFKC normalization |
| **Encoded payloads** | Base64/hex instruction injection | Layer 1 detects + removes |
| **Exfiltration URLs** | Markdown images with data in query params | Layer 1 strips suspicious URLs |
| **LLM delimiter spoofing** | Fake im_start, INST, Human: | Layer 1 strips all known delimiters |
| **Semantic injection** | Instructions disguised as text | Layer 2 Q-Agent best-effort detection |
| **LLM laundering** | P-LLM rephrases quarantined content | Not defended (requires CaMeL $VAR tokens) |

## 2. Security Architecture

### 2.1 Defense in Depth Layers

```
+---------------------------------------------------------+
| Layer 1: Deterministic Sanitization Pipeline             |
| - HTML parse + hidden element removal                    |
| - Script/style/noscript/meta tag stripping               |
| - HTML to Markdown conversion                            |
| - Unicode sanitization (zero-width, bidi, NFKC)         |
| - Encoded payload detection (base64/hex)                 |
| - Exfiltration URL detection                             |
| - LLM delimiter stripping                                |
+---------------------------------------------------------+
| Layer 2: Quarantined Q-Agent (Gemini Flash-Lite)         |
| - NO function declarations (no tools)                    |
| - NO google-genai SDK (no accidental tool config)        |
| - NO memory (stateless per request)                      |
| - Hardened system prompt                                  |
| - Structured JSON output (responseSchema enforcement)    |
+---------------------------------------------------------+
| Cumulative Intelligence: SQLite Blocklist                |
| - Write access: deterministic code ONLY                  |
| - Q-Agent cannot modify blocklist                        |
| - Sources that fail scans are remembered                 |
+---------------------------------------------------------+
| Trust Allowlist: Server-Side Configuration               |
| - Administrator-set, not agent-controlled                |
| - Trusted sources skip Q-Agent (cost optimization)       |
| - Untrusted sources get full L1+L2 scanning              |
+---------------------------------------------------------+
```

### 2.2 Q-Agent Architectural Quarantine

The Q-Agent's security comes from architectural constraints, not prompt engineering:

1. **No tools**: Request body contains no `tools` or `functionDeclarations` keys. Runtime assertions verify this.
2. **No SDK**: Uses raw httpx REST calls to Gemini API. The google-genai SDK is not installed, eliminating any possibility of accidental tool configuration.
3. **No memory**: Each request is stateless. No conversation history, no context carryover.
4. **No write access**: Q-Agent output is parsed by deterministic code. The Q-Agent cannot write to the SQLite blocklist or any other state.

### 2.3 Input Validation

All inputs are validated through Pydantic models:

- **URLs**: Must be valid HTTP/HTTPS
- **File paths**: No path traversal (..), text files only, size limited
- **Prompts**: String inputs (no injection risk to server itself)
- **Extra fields**: Rejected (Pydantic extra="forbid")

## 3. Supply Chain Security

### 3.1 Container Security

Built on **[Hummingbird Python](https://quay.io/repository/hummingbird/python)** for minimal CVE exposure.

### 3.2 Dependency Minimization

No google-genai SDK. Direct REST API calls via httpx eliminate the entire Gemini SDK dependency tree.

## 4. Security Checklist

Before each release:

- [ ] All inputs validated through Pydantic models
- [ ] Q-Agent request body verified: no tools, no functionDeclarations
- [ ] No shell execution
- [ ] No eval/exec
- [ ] Error messages scrub API keys (SecretStr)
- [ ] Dependencies scanned for CVEs
- [ ] Container rebuilt with latest Hummingbird base
- [ ] Gourmand passes (defensive_error_silencing check)

## 5. Reporting Security Issues

Report security vulnerabilities using [GitHub's private security advisory](https://github.com/crunchtools/mcp-trentina/security/advisories/new).

Do NOT open public issues for security vulnerabilities.
