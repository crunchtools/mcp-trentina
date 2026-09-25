# Cumulative Detection Memory (Blocklist)

When Trentina detects prompt injection in a source, it adds the source to a persistent SQLite blocklist. Future requests for the same source trigger an immediate warning — the system remembers what it's seen before, even across restarts.

## Why This Matters

Without a blocklist, every request for a known-malicious source re-runs the full defense pipeline. The agent gets the same warning every time, but there's no institutional memory. Worse, an attacker could keep trying slight variations, hoping that one of them slips past a probabilistic classifier on a lucky run.

The blocklist provides deterministic, instant detection for previously identified threats. Once a source is flagged, it stays flagged regardless of what the classifier thinks on subsequent runs.

## What Gets Recorded

Each blocklist entry contains:

| Field | Type | Example |
|-------|------|---------|
| `source_type` | text | `url`, `file`, or `content` |
| `source` | text | `https://evil.com/page` or `sha256:abc123...` |
| `domain` | text | `evil.com` (null for files/content) |
| `detected_at` | datetime | `2026-06-22T17:13:23Z` |
| `risk_level` | text | `critical` or `high` |

## How It Works

### Detection → Blocklist

A source enters the blocklist when `block` **refuses** it: any layer flagged it and the source is not allowlisted. The row is keyed by:

- **URLs**: the full URL
- **Files and directories**: the resolved path
- **Inline content**: the SHA-256 of the content

`flag` and `redact` record their detections too, but as observations (`blocked = 0`), so they never feed the blocklist. Until 0.31.0 every row was written blocked, which meant a flag fetch of a flagged page blocklisted it and the next flag fetch of the same page was refused.

### Blocklist → Refusal

The blocklist is checked before any bytes are fetched. `block` and `flag` refuse a blocklisted source outright, and the refusal offers `redact` when the caller's policy allows it. `redact` proceeds — it delivers only a verified extraction — and sets `blocklisted: true` in `_trentina_warning`.

### Viewing the Blocklist

The `quarantine_stats` tool includes blocklist summary data:

```json
{
  "blocklist": {
    "total_blocked": 9,
    "by_risk_level": {
      "critical": 4,
      "high": 5
    },
    "recent_detections": [
      {
        "source_type": "url",
        "source": "https://forge.rust-lang.org/release/process.html",
        "domain": "forge.rust-lang.org",
        "detected_at": "2026-06-22T17:13:23Z",
        "risk_level": "high"
      }
    ]
  }
}
```

## False Positives

Some legitimate sources trigger the classifier due to security-adjacent content (pages about prompt injection, security research, penetration testing documentation). These show up as `high` risk in the blocklist. The system warns but doesn't block in quarantine mode — the consuming agent gets the content with a warning attached.

`critical` risk entries are sources where the Q-Agent confirmed malicious intent. `high` risk entries are classifier-only detections that may include false positives.

## Storage

The blocklist is stored in the same SQLite database as the audit log and compression cache. The table is append-only and survives container restarts when the database is mounted on a persistent volume:

```bash
QUARANTINE_DB=/data/quarantine.db
```

## Related

- [Defense Pipeline](defense-pipeline.md) — how detections are generated
- [Quarantine Tools](quarantine-tools.md) — how blocklist warnings appear in tool responses
- [Audit Log](audit-log.md) — broader call recording beyond detections
