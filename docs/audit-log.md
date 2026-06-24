# Gateway Audit Log

Every tool call through the Trentina gateway is recorded in SQLite. The audit log captures who called what, whether it succeeded, how long it took, and what the defense pipeline found. This data drives allowlist tuning, error diagnosis, and usage monitoring.

## Why This Matters

Without observability, you're flying blind. Which tools are your agents actually using? Which backends are producing errors? How often does the defense pipeline flag content? The audit log answers these questions with data, not guesses.

## What Gets Recorded

Each gateway call writes one row to the `gateway_calls` table:

| Column | Type | Example |
|--------|------|---------|
| `timestamp` | datetime | `2026-06-23T10:42:11Z` |
| `profile` | text | `josui` |
| `backend` | text | `github` |
| `tool` | text | `list_issues_tool` |
| `success` | boolean | `true` |
| `duration_ms` | integer | `234` |
| `error` | text | `null` (or error message) |

## Accessing Audit Data

The `quarantine_stats` tool exposes audit data through the gateway itself:

```json
{
  "gateway_audit": {
    "total_calls": 5743,
    "days": 30,
    "by_tool": [
      {"backend": "ashigaru", "tool": "status", "calls": 1559, "ok": 1553, "errors": 6},
      {"backend": "github", "tool": "get_pull_request_checks_tool", "calls": 195, "ok": 195, "errors": 0},
      {"backend": "web", "tool": "quarantine_fetch_tool", "calls": 157, "ok": 133, "errors": 24},
      {"backend": "gw-work", "tool": "search_gmail_messages", "calls": 100, "ok": 100, "errors": 0}
    ]
  }
}
```

The top-N breakdown shows which tools get the most use and which have the highest error rates — direct evidence for where to focus allowlist tuning or backend debugging.

## Use Cases

### Allowlist Tuning

After running with `tools_allow: ["*"]` for a week, check the audit log to see which tools are actually used. Build an explicit allowlist from the data:

```
Top 10 tools for kagetora (last 7 days):
1. ashigaru__status (1559 calls)
2. github__get_pull_request_checks_tool (195 calls)
3. web__quarantine_fetch_tool (157 calls)
...
```

### Error Diagnosis

High error rates on a specific backend suggest connectivity issues, authentication problems, or backend bugs:

```
web__quarantine_fetch_tool: 157 calls, 24 errors (15% error rate)
web__safe_fetch_tool: 91 calls, 29 errors (32% error rate)
```

### Usage Patterns

Track which agents use which capabilities, how tool usage changes over time, and whether new backends are getting adopted.

## Storage

The audit table lives in the same SQLite database as the blocklist and compression cache (`trentina.db`). The table is append-only — rows are never updated or deleted. Database path is configurable:

```bash
QUARANTINE_DB=/data/trentina.db  # default on container
```

## Related

- [MCP Gateway](gateway.md) — where audit recording happens
- [Blocklist](blocklist.md) — detection events that trigger blocklist entries
- [Per-Agent Profiles](profiles.md) — per-profile audit scoping
