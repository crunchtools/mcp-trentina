# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

Entries prior to 2026-09-19 are back-filled from GitHub Release notes (RT #1484).
This project was previously named `mcp-airlock`; releases before 0.5.0 were cut
under that name.

## [Unreleased]

## [0.9.1] - 2026-09-21

### Fixed
- **Provisioned OAuth clients are registered with the provider's scope.** 0.9.0
  built them with no scope at all. The MCP SDK validates every requested scope
  against the client's registered scope, so each `/authorize` was refused with
  `error=invalid_scope` (`Client was not registered with scope openid`) and
  redirected straight back to the client carrying that error — before `/consent`
  and before Google. From the connector's side this looks like an immediate
  "Account linking is required", failing faster than the bug it was meant to
  fix. FastMCP's DCR path takes this value from `_default_scope_str`; a
  provisioned client has to be handed the same thing, so the clients are now
  built after the provider and carry its normalized scope string.

  0.9.0's tests covered storage, lookup, redirect URIs and the metadata
  document, but never the scope the authorization path actually checks. Two
  tests now pin it: the registered scope must equal the provider's, and every
  advertised scope must appear on the client.

## [0.9.0] - 2026-09-21

### Added
- **Statically provisioned confidential OAuth clients.** A profile's `oauth`
  block may now declare `client_id`, `client_secret_env` and
  `client_redirect_uris`, describing a client whose credentials an operator
  types into a third-party console rather than one that registers itself
  through DCR. The secret is named by environment variable, never written in
  the config file, so the "no secret in this block" rule the config documents
  still holds. A half-declared client (any one of the three without the others,
  or a `client_id` on a profile with `oauth.enabled` off) is refused at load
  rather than failing later in a way that is hard to read from the outside.

  gemini.google.com Custom Apps is the motivating case, and this is the last
  blocker in that connect flow. Its connector offers exactly three fields — MCP
  server URL, Client ID, Client Secret — and no Authorization or Token URL. So
  it discovers our authorization server from the MCP URL via RFC 9728 → RFC
  8414 and then authenticates to it as a *confidential* client using those
  credentials. Our metadata advertised `token_endpoint_auth_methods_supported:
  ["none"]`, telling a client holding a secret that the only supported method
  is no-client-authentication. Gemini abandoned the flow there: `/authorize`,
  `/consent` and `/auth/callback` all completed, and `POST /token` was never
  issued at all.

  This is 0.8.2's CIMD fix biting from the other side. Narrowing the advertised
  methods to `["none"]` is what pushed Gemini off the CIMD path and onto DCR —
  and simultaneously told it the Custom App credentials were unusable.

### Changed
- **The authorization-server metadata advertises `client_secret_post` when a
  provisioned client exists.** `OAuthProxy` hardcodes the advertisement to
  `["none"]` because it never enforces a downstream client secret, which was
  accurate for it and is no longer accurate for us: a provisioned client is
  resolved by `get_client` ahead of the DCR store, so the SDK's
  `ClientAuthenticator` performs a real `hmac.compare_digest` check and an
  expiry check against the stored secret. The method is advertised because it
  is now genuinely enforced, not to make a client proceed. With no provisioned
  client the document is untouched and still reads `["none"]`.

  PKCE remains the primary binding; the secret is a second factor, not a
  replacement. DCR-registered public clients are unaffected — `none` stays in
  the advertised list and their registration path is unchanged.

## [0.8.3] - 2026-09-21

### Fixed
- **OAuth: pin the RFC 8707 resource to the gateway endpoint so `/authorize`
  stops returning `invalid_target`.** FastMCP derives the protected-resource
  URL — the audience of issued tokens, and the value `OAuthProxy` compares the
  client's `resource=` indicator against — from `base_url` plus the path
  FastMCP mounts its *own* MCP app at. Trentina does not serve MCP from that
  mount: it serves `/gateway/<profile>/mcp` from its own routes and tombstones
  FastMCP's at a per-boot random `/mcp-internal-<hex>`. So the derived resource
  was an internal URL that appears in no discovery document and that no client
  can guess. gemini.google.com correctly took the resource from our RFC 9728
  metadata (`https://mcp.crunchtools.com/gateway/gemini-app/mcp`), it never
  matched, and every `/authorize` was rejected with `invalid_target` before the
  flow ever reached Google. The provider is now built with an explicit
  `resource_base_url` of the OAuth profile's gateway endpoint, and a
  `GoogleProvider` subclass passes no path to `set_mcp_path` so that value is
  used verbatim rather than having the internal path appended. This is the
  third and final blocker in the Gemini Custom App connect flow, after the
  issuer byte-match (0.8.1) and CIMD (0.8.2); `/authorize` now reaches Google
  and the callback returns a client code.

  Known limitation, logged as a warning at startup: `OAuthProxy` holds one
  resource URL, so with OAuth enabled on more than one profile only the
  first (sorted) profile authorizes and the rest fail `/authorize` with
  `invalid_target`.
- **L2: build each scan window from token IDs instead of a decode/re-encode
  round trip.** `classify()` slid its window over token IDs, then decoded each
  window back to text and re-tokenized it to build the model input. That cost a
  second tokenizer pass per window for a result identical on any real text
  (verified against the model's own tokenizer on prose, code, HTML, and
  non-Latin scripts) — and on binary decoded as text it silently *dropped*
  tokens, 242 of 302 in testing, because runs of U+FFFD do not survive a decode
  and re-encode. The window is now wrapped in the model's special tokens and
  padded directly from the IDs the tokenizer already produced, so a scan sees
  everything the tokenizer emitted. The window also now carries
  `max_length - num_special_tokens_to_add()` content tokens rather than
  `max_length`, which is what makes the special tokens fit instead of pushing
  content off the end of the segment.
- **L2: state the sliding window's guard band against content tokens.** 0.8.2's
  stride change (#142) set `WINDOW_STRIDE = 448` for a 64-token guard band, but
  measured it against `WINDOW_TOKENS` (512). A window carries only 510 tokens of
  input — the special tokens take the other two — so the delivered band was 62
  while the constant and its test both reported 64. New `WINDOW_CONTENT_TOKENS`
  and `WINDOW_SPECIAL_TOKENS` name the distinction, the stride moves to 446 to
  restore the 64 tokens #142 intended, and the geometry tests now measure the
  band the code actually delivers. This is the same constant-versus-
  implementation drift #142 set out to eliminate, one level down.

## [0.8.2] - 2026-09-20

### Fixed
- **OAuth discovery: stop advertising CIMD so Gemini falls through to dynamic
  client registration.** The gateway's `/.well-known/oauth-authorization-server`
  document advertised `client_id_metadata_document_supported: true`, because
  FastMCP's `OAuthProxy` sets that flag whenever CIMD is enabled (the default).
  But the proxy does not actually implement server-side CIMD (Client ID Metadata
  Documents, SEP-991). The MCP authorization spec makes a client attempt CIMD
  *before* Dynamic Client Registration whenever the flag is set, so
  gemini.google.com's Custom app connector fetched both discovery documents,
  chose the CIMD path, found nothing to service it, and reported "automatic
  registration with this server failed" — without ever POSTing to `/register`.
  The gateway now builds the provider with `enable_cimd=False`, which drops the
  flag (and the `private_key_jwt` token-endpoint auth method that rides with it),
  leaving `token_endpoint_auth_methods_supported: ["none"]`. A client now falls
  straight through to DCR, which the proxy does implement (and which returns 201
  for the public clients it issues). This is the second half of the Gemini
  connect fix begun in 0.8.1 (the issuer byte-match); the trailing-slash fix was
  necessary but not sufficient — Gemini re-fetched both docs post-0.8.1 and still
  never registered, because it was taking the CIMD branch.
- **OAuth discovery: the two documents now advertise the same scopes.** The
  RFC 9728 protected-resource document advertised the `openid`/`email`/`profile`
  shorthand while FastMCP's authorization-server metadata advertised the
  normalized full `googleapis.com` scope URIs. A client that read the shorthand
  here and requested it against an AS that lists only the full URIs can be
  refused at authorization time (`invalid_scope`). `OAuthContext` now captures
  the provider's normalized `scopes_supported` at startup and the
  protected-resource document advertises that identical list.

## [0.8.1] - 2026-09-20

### Fixed
- **OAuth discovery: authorization-server identifier now matches FastMCP's
  `issuer` byte-for-byte**, so gemini.google.com's Custom app connector completes
  dynamic client registration instead of reporting "automatic registration with
  this server failed". The gateway's own RFC 9728 protected-resource metadata
  advertised the authorization server as `https://host` (no trailing slash),
  while FastMCP renders the `issuer` in its `/.well-known/oauth-authorization-server`
  document through a pydantic `AnyHttpUrl`, which appends a slash (`https://host/`).
  RFC 8414 §3.3 requires a client to find the AS `issuer` identical to the
  identifier it discovered it by; strict clients (Gemini's connector, Google's
  ADK) reject the metadata on the mismatch and fall back to asking for a manual
  client ID and secret, never POSTing to `/register`. `OAuthContext` now captures
  the provider's exact `issuer_url` at startup and the protected-resource document
  advertises that string. FastMCP commits to the slashed issuer everywhere it
  matters (the RFC 9207 `iss` on authorization responses, the JWT `iss`), so
  matching it — rather than stripping the slash — keeps the whole flow internally
  consistent.

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
