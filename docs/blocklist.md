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

When the defense pipeline detects an injection:

1. L2 (classifier) or L3 (Q-Agent) flags the content as malicious
2. The source identifier is computed:
   - **URLs**: the full URL
   - **Files**: the file path
   - **Inline content**: SHA-256 hash of the content
3. The source is added to the SQLite blocklist with the detection timestamp and risk level

### Blocklist → Warning

On subsequent requests for a blocklisted source:

1. The source identifier is checked against the blocklist before the defense pipeline runs
2. If found, a `blocklist_warning` field is added to the response
3. The content is still processed (quarantine mode) or rejected (safe mode), but the warning tells the consuming agent that this source was previously flagged

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
QUARANTINE_DB=/data/trentina.db
```

## Related

- [Defense Pipeline](defense-pipeline.md) — how detections are generated
- [Quarantine Tools](quarantine-tools.md) — how blocklist warnings appear in tool responses
- [Audit Log](audit-log.md) — broader call recording beyond detections
