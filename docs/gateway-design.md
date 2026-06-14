# Gateway Mode — airlock as the trusted boundary for MCP traffic

**Status:** Design draft (v0.2, Option C — single-endpoint architecture)
**Branch:** `feat/gateway-design`
**Tracking task:** crunchtools/tmp #18 · RT #1438 (Option C)

---

## Summary

Airlock today exposes 6 web-content tools (`fetch`, `read`, `search`, `scan`,
`blocklist`, `stats`) that run untrusted content through a 3-layer prompt-injection
defense (L1 sanitize → L2 Prompt Guard 2 classifier → L3 quarantined Gemini
re-extraction) before returning anything to the LLM.

This design extends airlock with a second surface — a **per-consumer MCP gateway**
that proxies traffic to the 14 backend MCP servers running on lotor, applying the
same defense pipeline to every tool response on the way back, with per-profile
control of which tools each consumer sees and which defense layers run.

Net result: one chokepoint, one audit log, one Cockpit UI, one policy plane
covering both web fetches *and* MCP-server tool outputs.

---

## Mission restatement

Airlock's mission has always been the **trusted boundary between untrusted content
and the LLM**. Web-fetch happens to be the only surface currently implemented because
the LLM platforms Scott uses (Claude, Gemini) ship web search/fetch as native tools
and don't route them through MCP — so airlock had to provide replacement tools.

Every MCP server that returns content is the same threat: a wiki page, an RT ticket
comment, a Slack message thread, a Jira issue description, a Confluence page, an
email body — every one is a channel an attacker can plant prompt-injection payloads
in. None of them currently flow through airlock. The gateway extension closes that
gap without changing the mission.

---

## Problem

Three problems converge:

1. **MCP responses bypass airlock.** A malicious Confluence page, a Jira ticket
   description written by a hostile user, a phishing email rendered through the
   Gmail MCP — every one of those reaches the LLM unfiltered today. Airlock is
   the right boundary for this content but has no current path to it.

2. **Per-consumer policy lives in two places.** Josui's deny list lives in
   `~/.claude/settings.json`. Kagetora's deny list lives in Hermes's
   `config.yaml`. The patterns are identical (`delete_*`, `send_gmail_message`,
   `wordpress_delete_*`, etc.) but expressed differently, maintained
   separately, and the next consumer (Takeda/OpenClaw) would make it a third
   place to update. The policy plane wants centralization.

3. **Tool-definition context pollution.** The MCP fleet exposes ~575 tools,
   summing to ~137,000 prompt tokens of tool descriptions per turn. Per-consumer
   deny lists (Claude Code's `permissions.deny`, Hermes's `disabled_tools`) gate
   *execution* but the tool definitions still ship in every prompt. Filtering
   them at the `tools/list` response — *before* they reach the consumer — is
   the only mechanism that actually reduces context cost.

---

## Approach

> **Option C (2026-06-13):** the gateway is the **single** surface. The original
> `/mcp` web-tools endpoint is deprecated — airlock's own tools are folded into
> the gateway as an in-process `internal://` backend (conventionally named `web`),
> so one per-consumer endpoint behind one bearer token covers airlock's tools
> *and* the whole MCP fleet. There is no parallel surface to maintain.

The gateway endpoint family:

```
POST /gateway/<profile_name>/mcp        ← canonical, single surface
POST /mcp                                ← deprecated (404 on the fastmcp 3.1.1 base)
```

Each request to the gateway endpoint:

1. **Authenticates** the caller (bearer token in `Authorization` header, matched
   against the profile's configured token).
2. **Resolves** the consumer's profile (tool allowlist + defense config).
3. **Dispatches** the MCP call by backend URL scheme: `http(s)://` proxies to a
   remote MCP server via the `crunchtools` podman network (container DNS lookup
   — already how Kagetora reaches the fleet today); `internal://<label>`
   dispatches in-process to airlock's own FastMCP tool registry. Both paths
   return identical wire shapes to the consumer.
4. **On `tools/list` response:** drops tool definitions not in the profile's
   allowlist *before* forwarding to the consumer. This is where context savings
   come from.
5. **On `tools/call` response:** runs the response content through the configured
   defense layers (L1 always; L2 always; L3 optional per-profile) and returns
   sanitized content + detection metadata to the consumer.
6. **Audits** every passthrough (profile, backend, tool, detection scores, byte
   counts) to airlock's existing SQLite audit table.
7. **Surfaces** in the Cockpit plugin under a new "Gateway" tab.

Under Option C the standalone `/mcp` web-tools endpoint is deprecated; airlock's
own tools are reached through the gateway's `internal://` backend, so every tool
response — web fetches included — flows through the single gateway chokepoint.

---

## Profile schema

YAML in `/etc/airlock/profiles.yaml` (or `$AIRLOCK_PROFILES_PATH`), hot-reloaded
on file change (handled by Cockpit when profiles are edited from the UI).

```yaml
profiles:
  josui:
    auth:
      bearer_token_env: AIRLOCK_GATEWAY_JOSUI_TOKEN
    backends:
      web:                              # airlock's own tools, in-process
        url: internal://web
        tools_allow: ["*"]
        tools_deny: []
      mcp-slack:
        url: http://mcp-slack:8005/mcp
        tools_allow: ["*"]
        tools_deny: []
      mcp-mediawiki:
        url: http://mcp-mediawiki:8016/mcp
        tools_allow: ["*"]
        tools_deny: []
      mcp-atlassian:
        url: http://mcp-atlassian:8021/mcp
        tools_allow: ["*"]
        tools_deny: ["jira_delete_issue"]
      mcp-wordpress-crunchtools:
        url: http://mcp-wordpress-crunchtools:8002/mcp
        tools_allow: ["*"]
        tools_deny:
          - "wordpress_delete_post"
          - "wordpress_delete_page"
          - "wordpress_delete_media"
          - "wordpress_delete_comment"
      google-workspace-personal:
        url: http://google-workspace-personal:8000/mcp
        tools_allow: ["*"]
        tools_deny:
          - "send_gmail_message"
          - "delete*"
          - "batch_delete*"
      # ... rest of Josui's backends
    defense:
      sanitize: true                # L1 — always cheap, default on
      classify: true                # L2 — Prompt Guard 2 inference
      classify_threshold: 0.5
      quarantine: true              # L3 — Gemini re-extraction
      quarantine_threshold: 0.7
      audit: true

  kagetora:
    auth:
      bearer_token_env: AIRLOCK_PROFILE_KAGETORA_TOKEN
    backends:
      memory:
        url: http://mcp-memory:8765/mcp
        tools_allow: ["*"]
        tools_deny: []
        headers:
          Authorization: "Bearer ${MCP_MEMORY_API_KEY}"
      mcp-gemini:
        url: http://mcp-gemini:8006/mcp
        tools_allow: ["*"]
        tools_deny: ["gemini_delete_cache_tool"]
      google-workspace-personal:
        url: http://google-workspace-personal:8000/mcp
        tools_allow: ["search_gmail_messages", "get_gmail_*", "list_calendars", "get_events", "manage_event"]
        tools_deny: ["send_gmail_message", "delete*"]
      # ... narrower backend set
    defense:
      sanitize: true
      classify: true
      classify_threshold: 0.3       # more aggressive for autonomous agent
      quarantine: false             # L3 OFF — token-cost-sensitive (see §"L3 toggle")
      audit: true
```

### Allowlist semantics

- `tools_allow` supports `*` (all), exact names, and `prefix*` / `*suffix` /
  `*substring*` globs.
- `tools_deny` runs after `tools_allow` and wins on conflict.
- A tool is exposed to the consumer iff it matches `tools_allow` AND doesn't
  match `tools_deny`.
- The check runs against the *backend's* tool name (not the namespaced
  consumer-visible name).

### Consumer-visible tool names

Backend tools are exposed under their original names, namespaced by backend name
to avoid collisions — including airlock's own tools under the `internal://`
backend's name (conventionally `web`):

```
web__safe_fetch_tool
web__quarantine_fetch_tool
mcp-slack__slack_list_channels
mcp-atlassian__jira_search
google-workspace-personal__get_gmail_message_content
```

Matches the `mcp__<server>__<tool>` convention Claude Code already uses, and
Hermes accepts namespaced tool names natively.

---

## L3 toggle (token-cost control)

L3 (Q-Agent / quarantined Gemini re-extraction) is the only defense layer with a
non-trivial token cost — every L3-triggered call burns Gemini tokens for
re-extraction. Two controls:

1. **Per-profile static toggle**: `defense.quarantine: false` disables L3 for
   that profile entirely. L2 still runs and flags suspicious content in the
   audit log, but the response passes through to the consumer with a detection
   metadata sidecar instead of being re-extracted.

2. **Cockpit runtime override**: a global "L3 enabled" switch in the Cockpit
   backend, persisted to airlock's SQLite settings table, takes precedence over
   per-profile config. Lets Scott kill L3 fleet-wide during a Gemini outage or
   when chasing a quota issue without redeploying.

When L3 is disabled (either path), the response still carries the L1/L2
detection metadata sidecar so the consumer agent can decide whether to trust
or discard.

---

## Integration with existing 3-layer defense

| Layer | Reuse | New |
|---|---|---|
| L1 — sanitize | Existing `sanitize/` pipeline applied to MCP response content | None |
| L2 — Prompt Guard 2 | Existing classifier, same thresholds (per-profile-configurable) | None |
| L3 — Q-Agent | Existing quarantined Gemini path with `quarantine_threshold` trigger | Per-profile + runtime toggle |
| Audit | Existing SQLite events table; add `gateway_passthrough` row type | New columns: `profile`, `backend`, `tool` |
| P-Agent (policy) | Existing blocklist logic applies to backend MCP servers (block a backend if its responses keep tripping L2) | New: blocklist scope expands from URL to MCP-server URL |

The defense pipeline is mostly reused verbatim — what's new is the wrapper that
turns "fetched web content" into "MCP tool-call response content" and routes it
through. ~200 lines of FastMCP server code + ~100 lines of profile loader +
~100 lines of audit-log adapter.

---

## Auth model

**v1**: bearer token per profile. Token value read from the env var named in
`auth.bearer_token_env`. Consumer sends `Authorization: Bearer <token>`.

**Out of scope for v1**: OAuth 2.0, OIDC, per-user-within-profile. FastMCP's auth
middleware makes these clean v2 additions.

Tokens never appear in config files (only env var names do); env file lives at
`/srv/mcp-airlock.crunchtools.com/config/profile-tokens.env` with chmod 600 +
chcon etc_t per the crunchtools convention.

---

## Audit & Cockpit additions

Every gateway passthrough writes one row to airlock's SQLite audit table:

| Column | Type | Example |
|---|---|---|
| ts | datetime | 2026-06-13T10:42:11Z |
| profile | text | josui |
| backend | text | mcp-atlassian |
| tool | text | jira_search |
| op | text | tools/call \| tools/list |
| l1_score | real | 0.02 |
| l2_score | real | 0.71 |
| l3_triggered | bool | true |
| resp_bytes | int | 41882 |
| latency_ms | int | 2340 |

New Cockpit panel **Gateway**:
- **Top-N tools per profile (last 24h)** — informs allowlist tuning
- **Detection events timeline** — every L2 flag and L3 trigger, with drill-down to the response that tripped it
- **Profile editor** — read-write YAML editor with validation, writes back to `/etc/airlock/profiles.yaml`
- **L3 master switch** — global on/off toggle (token-cost control)
- **Real-time passthrough tail** — live view of in-flight gateway calls

The Cockpit plugin uses airlock's existing D-Bus interface for read access;
write paths (profile editor, L3 switch) go through new D-Bus methods that
update SQLite and the YAML file with locking.

---

## Migration & compatibility

Option C is a **hard cut on the airlock side** (the gateway is the only surface),
with consumers migrating at their own pace. Each consumer collapses its many MCP
entries — including the old direct airlock `/mcp` entry — into a single
gateway entry behind one bearer token. **Kagetora cuts over first** (smaller
blast radius, autonomous agent), then Josui.

**Kagetora (Hermes on lotor) — first:**
1. Add the `kagetora` profile to airlock config: the `web` (`internal://web`)
   backend + a narrowed http backend set.
2. Replace the 14 `mcp_servers:` entries in Hermes `config.yaml` with one
   `airlock-gateway` entry pointing at
   `http://mcp-airlock:8019/gateway/kagetora/mcp` (Bearer
   `${AIRLOCK_GATEWAY_KAGETORA_TOKEN}`).
3. Restart kagetora; verify a call exercises both an http backend
   (`mcp-gemini__gemini_query_tool`) and the internal backend
   (`web__safe_fetch_tool`); confirm the prompt-token count drops from ~146K
   toward the <50K target.

**Josui (Claude Code on Breetai) — second:**
1. Add the `josui` profile with the `web` backend + the full http backend matrix.
2. Replace the ~10 migrated `~/.claude.json` MCP entries + the old airlock entry
   with one `airlock-gateway` entry pointing at
   `http://127.0.0.1:8019/gateway/josui/mcp`. Genuinely-local servers (pcloud,
   trove, claude-in-chrome, …) stay as-is.
3. Shrink the `~/.ssh/config` `lotor-mcp` tunnel from 10 `LocalForward` lines to
   one (8019).
4. Confirm `web__safe_fetch_tool` returns sanitized content and a remote backend
   (`mcp-slack__slack_list_channels`) returns results — both via the same token,
   single endpoint.

Estimated context savings for Kagetora when narrowed to (web, memory,
mcp-gemini, google-workspace-personal): ~575 tools → ~150 tools, ~146K → <50K
prompt tokens.

---

## Deployment (lotor)

Same `/srv/mcp-airlock.crunchtools.com/` layout the airlock service already
uses on lotor. Adds:

- `/srv/mcp-airlock.crunchtools.com/config/profiles.yaml` — profile definitions
- `/srv/mcp-airlock.crunchtools.com/config/profile-tokens.env` — bearer tokens
  (chmod 600, chcon etc_t, env-file passed to systemd unit)
- `/srv/mcp-airlock.crunchtools.com/data/audit.db` — already exists for L1/L2/L3
  events; gains gateway-passthrough rows
- Cockpit plugin gains the Gateway tab — same `cockpit-airlock/` package, lives
  in `/usr/share/cockpit/airlock/`

No new container, no new port, no new systemd unit. The existing
`mcp-airlock.crunchtools.com.service` stays as-is; the airlock binary gains a
new endpoint family on its existing `127.0.0.1:8019` listener.

Cockpit visualization comes free with the existing Cockpit instance on lotor —
the Gateway tab appears alongside the current Airlock tab on first login after
the image bumps.

---

## Cascade integration

mcp-airlock is already in the cascade (FROM-graph parent: the Hummingbird Python
3.13 base; dispatch fanout already covers it). The version bump for this work
goes through the existing build pipeline:

- Buildah → Trivy (HIGH/CRITICAL block) → SBOM → Quay + GHCR push
- Parent-image-updated dispatches still fire on Hummingbird rebuilds
- No `schedule:` trigger
- SemVer bump: MINOR (0.3.0 → 0.4.0) — backwards-compatible addition

---

## Performance considerations

Per gateway call (worst case, L3 triggered):

| Step | Latency |
|---|---|
| Auth check + profile lookup | <1ms |
| Backend MCP call (over `crunchtools` network) | depends on backend (5-500ms typical) |
| L1 sanitization | <10ms |
| L2 classifier | 50-200ms (Prompt Guard 2 inference) |
| L3 quarantine (if triggered) | 1-2s (Gemini round-trip) |
| Audit log write | <5ms |

L3-off case (per profile): drops the 1-2s tail. L3 only fires when L2 > threshold,
so in steady state L3 contributes near-zero latency.

`tools/list` response (allowlist filter only, no content scan): <5ms overhead.

Streaming preserved end-to-end for SSE responses — airlock forwards chunks as
they arrive, applying L1 incrementally; L2/L3 buffer until the stream completes
(or until a watermark, configurable).

---

## Security considerations

- **Fail-closed defaults**: profile not found → 404; auth missing → 401; backend
  unreachable → 502 with retry-after; L2 classifier unavailable → fail-closed
  (response held, error returned to consumer) unless profile sets
  `defense.classify_fallback: allow`.
- **Token rotation**: tokens are env-file-loaded; rotation = update env file +
  systemd reload (no rebuild).
- **Server-to-server trust**: backends are trusted on the `crunchtools` network
  (loopback-bind only, no public reach). Airlock is the only thing talking to
  them through this path.
- **Audit immutability**: SQLite audit table is append-only (existing pattern);
  Cockpit shows but never edits.
- **Cockpit auth**: existing Cockpit auth (RHEL system auth) gates UI access.
  Profile-editor write access requires the existing `cockpit-airlock-admin`
  role.

---

## Non-goals / out of scope (v1)

- OIDC / OAuth (v2)
- Rate limiting (v2 — could fold into airlock's existing P-Agent blocklist)
- Caching backend responses (v2 — backends own their own caching)
- MCP resources / prompts passthrough — v1 covers `tools/list` and `tools/call`
  only; `resources/list`, `resources/read`, `prompts/list`, `prompts/get` come
  in v1.1 (mechanically similar to tools)
- Cross-profile aggregation (one consumer hitting multiple profiles)
- Backend rate-limit fanout (call goes 1:1, no parallel fan-out)

---

## Open questions

1. **L2 fail-closed vs fail-open default?** Recommend fail-closed for safety;
   profiles can override. Confirm.
2. **Per-tool L3 toggle in addition to per-profile?** Some tools' responses are
   structured-data-only (e.g., `slack_list_channels`) and L3 re-extraction adds
   no value. Heuristic: skip L3 when response content-type indicates pure JSON
   with no string fields > N chars. Worth doing in v1?
3. **Long-lived sessions**: streamable-http supports session resumption. Should
   airlock proxy session IDs transparently, or terminate at the gateway?
4. **P-Agent backend blocklist semantics**: if mcp-atlassian keeps tripping L2
   for a Josui profile, does the P-Agent blocklist apply per-profile or
   globally?
5. **Profile inheritance**: should profiles be able to inherit from a `default`
   profile to share common deny patterns?

---

## Implementation phases

| Phase | Scope | Estimated effort |
|---|---|---|
| 1 | Profile loader + auth + endpoint routing + tool allowlist filter (no defense pipeline yet) | ~half session |
| 1-final (Option C) | `internal://` airlock-tools backend; `/mcp` deprecated; gateway becomes the single surface | ~half session |
| 2 | L1 + L2 on tool-call responses; L3 with profile + Cockpit master switch | ~half session |
| 3 | Audit log integration + Cockpit Gateway tab (read-only) | ~half session |
| 4 | Cockpit profile editor + token rotation UI | ~half session |
| 5 | Migration: Josui + Kagetora cut over to gateway endpoints | ~one session |

Each phase is independently mergeable behind a feature flag (`AIRLOCK_GATEWAY_ENABLED=true`).

---

## References

- Existing airlock 3-layer defense: `src/mcp_airlock_crunchtools/sanitize/`,
  `quarantine/` (this repo)
- crunchtools MCP fleet on lotor: see [[mcp-centralization-lotor]] memory note
- Autonomous-agent constitution profile §V (kill switches): drives the L3
  toggle requirement
- FastMCP authentication middleware: https://gofastmcp.com/ (auth section)
