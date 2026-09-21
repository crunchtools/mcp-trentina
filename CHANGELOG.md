# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

Entries prior to 2026-09-19 are back-filled from GitHub Release notes (RT #1484).
This project was previously named `mcp-airlock`; releases before 0.5.0 were cut
under that name.

## [Unreleased]

## [0.8.0] - 2026-09-20

### Added
- **Google-backed OAuth per profile** (#137) — an optional `oauth` block on a
  profile (`enabled: bool`, `allowed_emails: list`) lets it accept a
  Google-backed OAuth token in addition to its static bearer, for clients that
  cannot send a static `Authorization` header (gemini.google.com's Custom app
  connector offers only "No authentication" or "OAuth"). Trentina runs as an
  OAuth proxy in front of Google — it presents the discovery, dynamic client
  registration, authorize, and token endpoints an MCP client expects and proxies
  the human login up to Google, so no self-hosted identity provider is needed.
  Static bearer is tried first and, on a match, nothing else runs, so every
  existing profile is untouched. An OAuth-enabled profile with no usable token
  answers 401 with `WWW-Authenticate: Bearer resource_metadata=…` pointing at
  its RFC 9728 metadata at `/.well-known/oauth-protected-resource/gateway/<profile>/mcp`
  (which the gateway serves itself, because FastMCP serves it only for its own
  mount path); a valid Google identity absent from `allowed_emails` gets 403.
  Emails are matched case-insensitively against Google's verified `email` claim,
  re-validated live on every request. The OAuth client is gateway-wide, read from
  `TRENTINA_OAUTH_GOOGLE_CLIENT_ID` / `_CLIENT_SECRET` (with `TRENTINA_OAUTH_BASE_URL`
  and an optional `TRENTINA_OAUTH_JWT_SIGNING_KEY`); a profile that enables OAuth
  with no client configured fails the gateway closed at startup. OAuth routes
  bind at startup and do not hot-reload — `reload_profiles` says so when an
  `oauth` block is added without a restart.
- **Profile roles, and role-scoped admin tools** (#133) — a new optional
  `role: agent | operator` on each profile, defaulting to `agent`. The gateway
  serves several agents from one config file, one database and one set of
  caches, and its four admin tools reached all of it from any profile allowed
  to call them: `quarantine_stats` returned the whole fleet's 30-day audit and
  the last ten detections, whose `source` is written `profile:backend:tool`;
  `reconnect_backend` resolved and reset a backend in any profile and listed
  every profile sharing it; `cache_flush` cold-flushed every profile's caches
  and reported how many were still warm. An agent profile now sees and acts on
  its own slice only — its audit rows, its detections, its backends, its
  section of `profiles.yaml` — and refusals name nothing, so a backend in
  another profile is refused exactly like one that does not exist. An operator
  profile keeps the gateway-wide view and the whole-file reload. A profile can
  never apply its own role change; that costs an operator reload or a restart.
  New `gateway/scope.py` is the single place any of this is decided.

### Changed
- **`reload_profiles` applies the caller's section, not the whole file**, when
  the caller is an agent profile (it still validates the whole file first, so a
  bad edit anywhere refuses). Operator profiles are unchanged. Result keys
  moved with the roles: `scope` replaces `changes_scope`, an agent result
  carries `applied` and a fixed `note` in place of `changes_withheld`, and the
  gateway-wide `profiles` block is operator-only.
- `quarantine_stats` reports a caller's own `defense` settings rather than the
  process defaults, and no longer hands an agent profile the classifier's host
  path or the fleet-wide compression aggregate.

### Fixed
- `cache_flush("gw")` used to evict every cached backend URL *containing* "gw"
  — `gw-work` and `gw-personal` together, in any profile. A backend name is now
  resolved by exact name in the caller's own profile, and for an operator
  through the profile registry rather than the cache keys.
- `get_blocklist_stats()` gained a `profile` filter, mirroring
  `get_gateway_call_stats()`.
- Tests no longer inherit a live `ActiveConfig` from whichever earlier test
  booted the gateway; `conftest` resets it between tests.

- **`reload_profiles` gateway admin tool** (#119) — applies a `profiles.yaml`
  edit without restarting the gateway. Until now a profile edit required a
  restart, and a restart re-judges every tool description through the three
  defense layers before the first `tools/list` answers (40+ minutes on the
  CrunchTools deployment, with every connected session dropped). Editing the
  file without restarting did nothing at all, silently. The reload validates
  the whole file before swapping — a bad edit keeps the running config — swaps
  the profiles in place, invalidates only the affected profile aggregates, and
  returns a per-profile diff. It keeps the perimeter verdict cache, so a
  profile-only edit re-judges nothing; changing a profile's `defense`
  thresholds re-judges that profile, which is the cost of changing the policy
  the verdicts were reached under. Sections that bind at startup
  (`llm_providers`, `matrix`, and ingress routes) are reported in
  `not_applied` instead of being reported as applied.

### Fixed
- A profile tool-list aggregation already in flight can no longer write a
  stale aggregate into the cache after an invalidation — it is now discarded.
  The same window existed for circuit-breaker evictions.
- `docs/internal/gateway-design.md` claimed profiles were "hot-reloaded on file
  change". There was no file watcher and no reload path; corrected to name the
  mechanism. `docs/profiles.md` likewise said backend header env vars expand at
  request time — they expand once, at load.

## [0.5.0] - 2026-06-23

**MCP-Airlock is now Trentina.** Named after the 1377 quarantine system from
Ragusa (near Dubrovnik) — ships anchored on abandoned islands for 30 days
(*trentina*) before entering the city. The precursor to quarantine.
Blog announcement: https://crunchtools.com/trentina/

### Changed
- **Package:** `mcp-airlock-crunchtools` → `mcp-trentina-crunchtools`.
- **Module:** `mcp_airlock_crunchtools` → `mcp_trentina_crunchtools`.
- **Container:** `quay.io/crunchtools/mcp-airlock` →
  `quay.io/crunchtools/mcp-trentina`.
- **Env vars:** `AIRLOCK_*` → `TRENTINA_*`.
- **MCP Registry:** `io.github.crunchtools/trentina`.
- Unchanged: the architecture, three-layer defense pipeline, Q-Agent isolation,
  gateway proxy, and parameter guards.

## [0.2.2] - 2026-03-15

### Fixed
- D-Bus policy now allows non-root users to own `com.crunchtools.Airlock1`
  (needed for container and user-mode operation).

### Changed
- Retained the explicit root policy alongside the default policy.
- Container image rebuilt with D-Bus + EventBus support.

## [0.2.1] - 2026-03-15

### Added
- **D-Bus interface** (`com.crunchtools.Airlock1`) — methods for querying
  pipeline state, signals for live event streaming.
- **cockpit-airlock Cockpit plugin** — real-time visualization of the defense
  pipeline in the Cockpit Tools sidebar.
- **Internal EventBus** — all tool functions emit structured events for external
  consumers.
- **RPM packaging** — `cockpit-airlock` noarch RPM attached to the release.

## [0.2.0] - 2026-03-10

The GitHub Release for this tag carries only a compare link, so no authored
summary exists to back-fill from. See
https://github.com/crunchtools/mcp-airlock/compare/v0.1.0...v0.2.0.

## [0.1.0] - 2026-03-09

No GitHub Release was created for this tag, so no authored release notes exist to
back-fill from.
