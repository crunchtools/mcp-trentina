# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

Entries prior to 2026-09-19 are back-filled from GitHub Release notes (RT #1484).
This project was previously named `mcp-airlock`; releases before 0.5.0 were cut
under that name.

## [Unreleased]

## [0.19.1] - 2026-09-22

### Changed
- **`preprocess/` is documented as transformation, not reduction — and
  invariant 1 is restated as an asymmetry.** The old wording was "a
  pre-processor never makes a security decision. It only reduces." Both halves
  were wrong.

  It was never reduction-only. `volatile.normalize()` rewrites timestamps and
  identifiers into placeholders — the fingerprinting policy invariant 2 rests
  on — and its size effect is incidental and runs both ways. `structured.py`
  re-serializes with indentation, which is more parseable and larger.

  And the package filters on every run: `petit` deletes lines, `structured`
  drops array elements, `email` drops quoted reply chains, with three tests
  named `test_dropped_*_are_gone` pinning exactly that. Filtering is inherently
  security-adjacent, so "never makes a security decision" denied what the code
  does, and that mis-framing ruled out designs it had no business ruling out.

  The real constraint is directional: **a pre-processor may subtract, never
  absolve.** Dropping is always permitted, because a byte that is deleted
  reaches no one — which is exactly why colliding a payload into a collapsed
  group destroys it. What is forbidden is the other direction: never mark
  content clean, never shorten or skip `defend()`, never let output be trusted
  more than input. Strictly no weaker, and honest about the package's
  behaviour.

  Invariant 2 now says out loud that the collision argument depends on
  DELETION rather than on getting smaller, so a future reshaping processor
  cannot assume cover it does not have. `scanview/base.py` keeps its sibling
  contrast coherent against the new wording.

  Documentation only — no identifiers, config keys or behaviour changed, and
  all 1539 tests pass with no test file edited.

### Fixed
- Invariant 3 claimed the pre-processing sidecar "travels two places: the
  audit log ... and L3's briefing". Only the briefing is real: `router.py`
  reads the sidecar solely to build L3 context, and
  `PreProcessOutcome.sidecar()` has no caller in `src/` at all. Now states
  what is true and marks the audit-log half as intended-but-unbuilt.
- `PreProcessResult.ratio` documented "1.0 means nothing happened", which is
  false for a transformation that reshapes without changing length — `applied`
  is the signal. Also records that `.ratio` itself is unread.
- The L3 briefing asserted a transformed artifact "is a sample of a larger
  payload", which is untrue when nothing was dropped. Now conditional on
  having actually shrunk.
- `docs/response-guards.md` linked "pre-processors" to `docs/compression.md`,
  which documents LLM compression of tool *descriptions* — a different
  feature. Points at the pre-processing section of `docs/token-routing.md`.
- **Finished the `com.crunchtools.Airlock1` -> `com.crunchtools.Trentina1`
  D-Bus rename, which had been half-applied since the airlock -> trentina
  rename.** `cockpit-trentina.spec` and `trentina.js` were moved to the new
  name; `dbus_interface.py`, the policy file and the `Makefile` were not. Two
  consequences, one loud and one silent:

  The RPM build has failed on every release since — `%install` referenced
  `dbus/com.crunchtools.Trentina1.conf`, which did not exist. PyPI and the
  container images published normally, so the break was confined to the
  `build-rpm` job and went unnoticed.

  The quieter one: the Cockpit plugin asked the system bus for
  `com.crunchtools.Trentina1` while the service owned
  `com.crunchtools.Airlock1`, so the dashboard could never have connected.
  Nothing had the RPM installed — it never built — so nothing depended on the
  old name and the rename breaks no deployment.

  Also corrected the spec's `%changelog` date: 15 March 2026 was a Sunday, not
  a Saturday, which rpmbuild reported as a bogus date on every build.

## [0.19.0] - 2026-09-22

### Added
- **Response guards (`response_guards`) — the egress half of parameter
  guards.** Parameter guards only see what the agent sent, which is enough for
  `send_gmail_message` and useless for a semantic tool: an agent asking a
  memory backend for "my employer's OS roadmap" sends nothing matchable, and
  the restricted record arrives in the *response*, which the request-side check
  never reads. `response_guards` applies the same `ParameterConstraint` —
  through one shared `evaluate_constraint`, so request and response really do
  run the same evaluator — to a backend's result.

  A guard addresses a key of `structuredContent`, or the reserved name
  `content` for every text block joined together. A match rejects the whole
  response: scrubbing the matched portion and delivering the rest would turn
  the guard into a leak oracle an agent could query its way around. The error
  names the field, never the content.

  The check runs on the raw result, before reduction and before the perimeter
  scan — pre-processors paraphrase, and a guard reading the reduced artifact
  could be walked past a literal a model rewrote. It runs on internal backends
  too, which skip reduce and scan: those skip because that content was already
  filtered where it entered, while egress policy is about who is asking.

  This is a literal glob filter, not a classifier. A paraphrase of a denied
  term passes, and when a whole backend is off-limits for an agent, cutting its
  tools from `tools_allow` is the cheaper and stronger control. See
  `docs/response-guards.md`. (RT #1500)
- **`denied_response_guard` outcome**, in the `blocked` group so a block reads
  as policy rather than failure. Kept distinct from `denied_guard`: this is the
  one denial that still spends the upstream call.

### Changed
- The reload tool's diff now reports `response_guards` alongside
  `parameter_guards`, keyed by field name and never echoing a pattern.

## [0.18.0] - 2026-09-22

### Added
- **Matrix E2EE termination: the perimeter can finally read message bodies.**
  Until now, message bodies in an encrypted room were ciphertext at the proxy.
  An injection in a chat message crossed Trentina as an opaque blob and became
  plaintext inside the agent, past the perimeter — the gap
  `docs/defense-pipeline.md` has always described honestly. Trentina now reads
  room keys from the homeserver's encrypted backup and decrypts events **to
  build a scan view only**. The response forwarded to the client is the
  upstream ciphertext, untouched; matrix.org never sees plaintext and the
  agent still performs its own decryption.

  Trentina takes no Matrix device identity, uploads nothing, and issues only
  GET requests. Recovered plaintext is never forwarded, never written to disk,
  and never logged in full. Nothing is persisted: a Megolm session key is a
  permanent decryption capability, and `/data` already holds
  attacker-supplied content.

  Three properties are load-bearing rather than incidental. The backup's
  **public key is verified at startup** against the one the recovery key
  derives, so a wrong key is a refused start rather than a silent inability to
  decrypt anything. Key fetches are **per-room, single-flight and
  cooldown-limited** — a rate limit, not a cache tuning, because session IDs
  arrive inside events and without it any room member could turn every `/sync`
  into N homeserver round-trips inside the request path. And **decrypted text
  goes back through the same generic rules as anything else**: plaintext
  recovered from ciphertext is no more trustworthy than plaintext that arrived
  in the clear.

  Events that cannot be read are reported by identity and counted, never
  passed over in silence. `to_device` olm events are excluded from that rate,
  because key backup does not cover olm and counting them would pin the metric
  high for ever.

  Off by default, behind `scan_view.decrypt.enabled`. `vodozemac` ships as the
  optional `matrix` extra, so a deployment asking for decryption on a platform
  without the wheel fails at config load rather than at request time.

## [0.17.0] - 2026-09-22

### Changed
- **Advertise CIMD again (Client ID Metadata Documents, SEP-991).** 0.8.2
  disabled it because `OAuthProxy` set
  `client_id_metadata_document_supported=true` while implementing nothing
  behind it, so a client that preferred CIMD took a dead branch and gave up
  without registering. That premise no longer holds: fastmcp 2.14.4 ships
  `CIMDClientManager` (`fastmcp/server/auth/cimd.py`) with SSRF-safe document
  fetching, `Cache-Control`/`ETag` validation, a response size cap and
  `private_key_jwt` verification, wired into `get_client` and the authorize
  path. Meanwhile the MCP authorization spec (2026-07-28) now orders
  pre-registered, then CIMD, then DCR, and marks DCR deprecated — so
  suppressing the flag advertises this gateway as older than it is.

  The redirect allowlist added in 0.16.0 covers this path too: the manager is
  constructed with the same `allowed_redirect_uri_patterns` DCR uses, so CIMD
  is not a way around the callback restriction. Pinned by a test.

  DCR keeps working and stays advertised, so `claude-web` and Claude Code are
  unaffected — clients that prefer DCR still get it.

### Notes
- **Corrected after release.** This entry originally stated that
  gemini.google.com could not connect because its Custom App connector was
  defective, and that Cloudflare had been "ruled out with captures". Both
  claims were wrong, and the second one inverted the actual cause.

  gemini.google.com connects fine. The blocker was **Cloudflare Bot Fight
  Mode** challenging Google's OAuth client: `GET` requests passed, so discovery
  always succeeded, while every `POST` was scored as bot traffic and dropped at
  the edge. A server-side OAuth client cannot solve a JavaScript challenge, and
  the free plan exposes no firewall log, so the drops were invisible. That is
  why `POST /register` and `POST /token` appeared never to be sent.

  The mistake that sustained it: Google's OAuth client sends
  `User-Agent: OpenAuth`, not `Google`. Log filters written against `Google`
  matched Gemini's tool traffic but silently excluded every registration and
  token request, which made "the client never POSTs" look like a finding
  rather than a filtering error.

  Confirmed by turning Bot Fight Mode off and re-proxying: registration,
  callback and token exchange all complete from Cloudflare edge addresses, and
  `gemini-web` serves tools over ordinary OAuth. Releases 0.13.0 through
  0.16.0 fixed four real defects along the way, but none of them was this. See
  RT #1502 for the full evidence.

## [0.16.0] - 2026-09-22

### Security
- **Self-registering clients may no longer name any callback they like.**
  `/register` is unauthenticated by design, and given no allowlist FastMCP
  accepts any https URL a client registers for itself
  (`redirect_validation.py:451-454`). That is an authorization-code theft path
  behind a single consent click: register a client named "Claude" pointing at
  an attacker-controlled host, send the operator a crafted `/authorize` link,
  and their code is delivered to the attacker — who exchanges it and holds a
  token carrying the operator's verified identity, which satisfies
  `allowed_emails` because it genuinely is them. Found by an adversarial
  review; pre-existing, not introduced by a recent change.

  `DEFAULT_ALLOWED_REDIRECT_URIS` now ships closed: loopback on any port (the
  code lands on the user's own machine, so an attacker who can read it already
  owns the host) plus the two fixed claude.ai/claude.com connector callbacks,
  which are identical for every user of that product. `claude.ai`'s was taken
  off the wire rather than from documentation.

- **New `oauth.allowed_redirect_uris`**, for callbacks the defaults cannot
  cover. Entries must be **exact https URLs**; a wildcard is refused at load
  with an explanation. gemini.google.com is the worked example of why:
  every Google user's callback lives under
  `oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-<id>-<host>`,
  so allowing that prefix would admit an attacker's own user-bound callback and
  the control would be worth nothing. The operator's exact URL blocks every
  other one on the same host. A profile's existing `client_redirect_uris` are
  folded in automatically, so a provisioned seat needs no extra configuration.

### Documentation
- `docs/authentication.md` gains **Which callbacks a client may register** — the
  attack in four steps, the shipped defaults and why each is safe, how to add
  your own, and a section on why wildcards are refused that uses Gemini's
  per-user callback to show the difference between a real control and a
  decorative one.

## [0.15.0] - 2026-09-22

### Changed
- **A profile now needs at least one authentication method, of any kind —
  not a bearer token specifically.** `auth` becomes optional and a model
  validator refuses any profile with neither `auth.bearer_token_env` nor
  `oauth.enabled`.

  `auth` was required until now, so every profile carried a static bearer and
  the "nothing is unauthenticated" property held by accident. That had a real
  cost: the only way to add OAuth to a seat was to *also* give it a permanent
  anonymous credential, and since the static bearer is checked first, that
  credential bypassed the OAuth entirely — the opposite of what an operator
  adding OAuth believes they are doing. An OAuth-only seat was simply not
  expressible.

  Bearer-only, OAuth-only and both-together are all valid now; neither still
  fails at load rather than quietly serving an open seat. `verify_bearer`
  distinguishes "this profile has no static bearer" from "its token did not
  resolve", which are different faults.

### Documentation
- Corrected `docs/authentication.md` and the `register_client` docstring on when
  a client secret is issued. Both said "only when the client asks for one".
  RFC 7591's default is a confidential client and the MCP SDK follows it, so a
  registration that *omits* `token_endpoint_auth_method` is treated as
  `client_secret_post` and gets a secret. It is opt-out, not opt-in. The Python
  MCP client and FastMCP's client both send `"none"` explicitly, which is why
  Claude Code is unaffected. Also documented that the secret never expires, and
  why: an expiring secret would strand a connector that cannot re-register.

## [0.14.0] - 2026-09-22

### Added
- **More than one OAuth profile per gateway.** FastMCP's `OAuthProxy` stores a
  single `_resource_url` and refuses every other RFC 8707 resource indicator
  with `invalid_target`. Correct for one OAuth seat; an outage for two, because
  the pin goes to whichever profile sorts first and the other one's every login
  fails — the 0.8.3 incident. Both claude.ai and gemini.google.com send the
  indicator, so this was not hypothetical: it is why the gateway ran exactly one
  OAuth seat until now.

  The indicator is now validated against every proxied profile's resource URL
  and cleared before delegating. Clearing is what makes the base check skip, and
  it is safe only because a value that is not one of ours has already been
  refused — `invalid_target`, same as before.

  The token audience stays gateway-wide (`proxy.py:785`), so it cannot tell two
  seats apart. The boundary between profiles is `allowed_emails` plus the tool
  allowlist, not the audience. Profiles whose allowlists differ now warn at
  startup, because that is the case where an operator believes in an isolation
  that does not exist.

### Documentation
- `docs/authentication.md` gains **How proxy mode actually works** — the two
  credential legs (client→Trentina, Trentina→Google) and why the Google Cloud
  credential is one per *server* rather than one per profile; the four-step
  login sequence; that Google performs authentication while Trentina performs
  authorization, and `allowed_emails` is the only thing between a stranger with
  a Google account and the gateway; and a table of why this beats a static
  bearer, including the caveat that a static bearer on the same profile is
  checked first and wins.

## [0.13.0] - 2026-09-22

### Fixed
- **Dynamic client registration now issues a client secret when one is asked
  for.** FastMCP's `OAuthProxy` discards the secret the MCP SDK mints and
  rewrites every registration to `token_endpoint_auth_method="none"`, on the
  reasoning that the proxy holds the upstream credentials and never checks a
  downstream one. That reasoning stops holding for a client that *requires* a
  confidential registration.

  gemini.google.com Custom Apps is such a client: Google Account Linking
  authenticates at the token endpoint with a client id **and** secret. A
  registration answered with "you are public, here is no secret" does not
  satisfy what it asked for, so Gemini reported "automatic registration failed"
  and stopped — which is why nothing was ever logged on our side. Across two
  days of captures Google issued GETs for both discovery documents and never a
  single POST to `/register` or `/token`; the flow ended before it had anything
  to send.

  A registration requesting `client_secret_post` now keeps the SDK's
  256-bit secret, and the stored client record carries it, which is what makes
  the SDK's `ClientAuthenticator` enforce it at `/token` rather than merely
  advertise it. A registration requesting `none` is untouched, so Claude Code
  and every other DCR client keep the public registration they already have.

  Only `client_secret_post` is honoured: the SDK reads `client_id` from the form
  body before it looks at the `Authorization` header, so `client_secret_basic`
  would reject the RFC 6749 §2.3.1 form that omits it, and advertising a method
  that half works is worse than not offering it.

### Changed
- `token_endpoint_auth_methods_supported` advertises `client_secret_post`
  unconditionally, not only when a statically provisioned client exists. A
  client reads that document **before** it registers and uses it to decide
  whether this server can issue the confidential registration it needs;
  advertising only after the fact left it with nothing to go on.

### Documentation
- `docs/authentication.md`: corrected the delegated-issuer section. Delegating
  to `https://accounts.google.com` was tried against gemini.google.com and
  refused with "This MCP server is not yet supported" — the connector requires
  the MCP server to be its own authorization server. The mechanism remains
  supported for other IdPs; it is not the answer for Gemini Custom Apps.

## [0.12.0] - 2026-09-22

### Added
- **Per-profile delegated OIDC authentication.** A profile's `oauth` block now
  takes `issuer` and `audience_env`. With them set, Trentina stops being the
  authorization server for that profile: it advertises the external issuer in
  the profile's RFC 9728 document, the client authenticates directly against
  that IdP, and Trentina verifies the token and applies `allowed_emails`.
  Google is wired and tested; the config is generic so another issuer is a
  verifier plus an allowlist entry. Proxy mode remains the default and is
  unchanged.

  This is the last blocker in the gemini.google.com Custom App connect flow.
  That connector offers three fields — MCP server URL, Client ID, Client Secret
  — and no authorization or token URL, so it read our document, found Trentina
  named as the authorization server, and refused to token-exchange against an
  AS it has no relationship with. Live captures showed `/authorize`, `/consent`
  and `/auth/callback` all completing, a client code minted and redirected with
  a verbatim `state` and byte-correct RFC 9207 `iss`, Google fetching both
  discovery documents server-side — and `POST /token` never issued, not once.
  Naming Google in that document instead is what unblocks it.

  Trentina never receives the external client secret. It holds only the client
  ID, to pin the token's `aud`.

- **`docs/authentication.md`** — all four mechanisms (static bearer, OAuth
  proxy with DCR, OAuth proxy with a provisioned confidential client, and
  delegated issuer) with a decision table, the failure mode of each, and the
  security rules. The OAuth material moves out of `docs/profiles.md`, which
  keeps the schema, rather than being duplicated.

### Fixed
- **The RFC 8707 resource pin is computed over proxied profiles only.** It used
  the first OAuth-enabled profile by sort order, so the moment a delegated
  profile sorted first — `gemini-app` before `josui` — the proxy would pin its
  resource to a profile that does not use it and fail every proxy-mode
  `/authorize` with `invalid_target`. That is the 0.8.3 outage, re-created for
  the profiles the change does not touch. Latent until now; a regression test
  pins it.
- **The 401 challenge follows RFC 6750 §3.1.** `error="invalid_token"` is sent
  only when a bearer was presented and refused. A request carrying no
  credential gets a bare `Bearer resource_metadata="…"`, because §3.1 says a
  server SHOULD NOT include an error code when the request lacks any
  authentication information — and one code path serves both cases.
- **`oauth_route_registered` reflects whether a proxy was built,** not merely
  whether OAuth is configured. With a delegated-only gateway the old form would
  report true, so an operator adding a proxied profile by reload would be told
  it applied and get a silent 401 loop.
- **`reload_profiles` reports delegated-mode edits it cannot apply,** on both
  the operator and agent paths — the agent path previously reported no
  unapplied settings at all. A verifier and its advertised issuer are bound at
  startup like `llm_providers`. `allowed_emails` still applies live.

### Security
- **Audience binding is mandatory and enforced across profiles.** A Google
  access token verifies for *any* OAuth client unless its `aud` is pinned, so
  an unpinned delegated profile would accept a token minted for any app an
  allowlisted human ever authorized — carrying the same verified email the
  allowlist checks. `issuer` requires `audience_env`; two delegated profiles
  may not share an audience; and no audience may equal
  `TRENTINA_OAUTH_GOOGLE_CLIENT_ID`, or the profile would accept every upstream
  token the proxy holds.
- **Delegated and provisioned client config are mutually exclusive.** The
  provisioned fields register a client against our own authorization server,
  which a delegated profile does not run. Combined, that credential would be
  registered into the shared proxy and become a live confidential client for
  the *other* profiles' authorization server.
- **The token is sent to Google in a POST body, not the query string.** Google
  documents `GET /tokeninfo?access_token=…`, but HTTP clients log request URLs
  at INFO, so the documented form writes live bearer tokens into the journal
  the moment anyone raises the log level. Caught by a test asserting no token
  reaches the logs.
- **Rejected tokens are cached briefly; unreachable-Google is never cached.**
  Proxy mode checks a JWT signature locally before doing anything expensive;
  delegated mode has no local pre-check, so without this any unauthenticated
  request with any bearer string would buy an outbound call to Google — and
  Google's tokeninfo is quota'd, so a flood could lock the real user out. Only
  rejections Google pronounced are remembered, which cannot extend any valid
  token's life, so revocation still takes effect on the very next request.
  Distinguishing a refusal from an outage is why this uses its own verifier
  rather than fastmcp's, which collapses both to `None`.
- **Successful OAuth authorizations are logged** with profile, subject, email,
  audience and an 8-character token digest. Refusals already logged a reason;
  acceptances logged nothing, so there was no way to answer who had used a
  profile. Tokens themselves never reach the logs in either case.

## [0.11.1] - 2026-09-21

### Fixed
- **L2 no longer pads every input to 512 tokens.** `classify()` padded each
  model input out to the full context window, so a 15-token chat message cost
  the same as a 512-token one. The exported graph declares both inputs as
  `['batch_size', 'sequence_length']` — the sequence axis is dynamic — and
  batch is always 1 here, so there was never a second row to line up against.
  The padding was a formatting habit, not a model constraint.

  Measured against the real model: a 15-token message 791 ms -> 52 ms (15.2x),
  a Nagios alert 570 ms -> 47 ms (12.2x), a tool description 564 ms -> 36 ms
  (15.7x). Across the adversarial corpus plus a long windowed case, **36.1 s ->
  7.9 s (4.6x) with zero label changes and zero score deltas above 1e-6** —
  the verdicts are bit-identical, verified against the shipped code path with
  the modified module mounted over the installed one.

  This mattered little when every scan filled a window. It matters a lot now:
  with scan-view extraction the typical payload is far below one window, so
  the common case was paying roughly 15x for zeros. Full windows are
  unaffected; only the final partial window of a long scan changes shape.

## [0.11.0] - 2026-09-21

### Added
- **Scan-view extractors: the pipeline no longer has to read the whole
  payload.** A measured Matrix initial sync put 68,042 characters in front of
  the classifier, of which 45,552 were Megolm ciphertext, ~15,000 were
  repeated JSON key names, and 245 were human-readable prose. The scan spent
  46 seconds reading base64 it cannot decrypt, which is long enough that
  OpenClaw's 30-second readiness budget expires and the agent never connects
  at all — a perimeter slow enough to be skipped is not a perimeter.
  `scanview/` adds a driver type that selects what the pipeline reads, with
  three mechanisms: structural skipping of strings incapable of carrying
  language, deduplication of exact repeats, and sampling of skipped openings
  as a backstop. **Measured on the live payload: 68,042 -> 3,856 characters,
  a 17.6x reduction.**

  This is a sibling of `preprocess/`, not an extension of it, because the
  safety property inverts: a pre-processor's output is what gets delivered, so
  what it drops nobody sees, whereas an extractor selects a subset to scan
  while the full original is delivered. Five invariants replace the borrowed
  three, including "skipping is structural, never semantic" — no trusted-room
  or trusted-sender list, ever — and "fail open to MORE scanning, never less".
  The default extractor is `full`, which is exactly today's behaviour, so this
  changes nothing until an operator opts in.

- **Per-profile scan-view policy, channel locking and RBAC.** Extractors
  declare which ingress channels they understand, and naming one on a channel
  it does not declare is a load-time error rather than a silently wrong
  perimeter. `extractor` is operator-only: an agent reloading its own profile
  may retune its sampling budget, coverage floor and deadline, but the fields
  deciding how much of a payload is read at all are held and reported in
  `not_applied`. An agent does not control profiles.yaml, but it does control
  when a reload happens, and "cannot write the file" is a weaker guarantee
  than "cannot apply the field".

### Fixed
- **A partial scan of a Matrix response no longer looks like a clean one.**
  `ClassifierResult.truncated` — L2 ran out of context window and read only
  part of the content — was honoured by the tool path and the alert ingress
  but not by the Matrix proxy, which annotated on `flagged` alone. A `/sync`
  whose tail was never classified was therefore delivered indistinguishable
  from one that came back clean. The same was true when the ONNX model failed
  to load and L2 never ran at all. Fixed at the root cause: the annotation is
  now built in one place, `gateway/warning.py`, shared by the tool path and
  the Matrix proxy. The triplication is *why* the Matrix copy was missed, and
  a fourth copy would have been missed too. (The alert ingress still builds
  its own, because it derives `risk_level` from its own detection counts
  rather than from the verdict; reconciling the two risk models is a
  behaviour change to that path and is tracked separately.)
- **The Matrix scan now has a deadline.** `defend_json` runs L2 and may call
  L3 — a network round-trip to a third-party LLM — with no timeout around it,
  while a `/sync` sits on the client's critical path. OpenClaw gives a channel
  30 seconds to become ready and starts over if it does not, so a slow judge
  did not degrade Matrix, it stopped it. The judgement is now bounded at 20
  seconds; on expiry the body forwards (fail open, as the rest of this path
  does) carrying a `scan_timeout` warning, because an unscanned response must
  never look clean.

### Added
- **`_FILE` indirection for every credential env var.** Any credential the
  gateway reads from `FOO` is now equally readable from the file named by
  `FOO_FILE`, which is the shape podman secrets, Kubernetes secret volumes and
  systemd `LoadCredential=` actually produce. The value then lives in a
  mode-0600 file instead of in `/proc/<pid>/environ`, where anything able to
  inspect the container can read it. `_FILE` takes precedence when both are
  set, per the crunchtools mcp-server profile: a mounted secret is the
  explicit deployment-time answer and a stale inherited env var must not
  quietly outrank it. A secret file that is named but unreadable is a hard
  config error rather than a silent fall-through, and loose file permissions
  warn without failing the load (constitution Section X). Routed through every
  existing consumer — bearer tokens, `llm_keys`, alert ingress tokens and
  forward secrets, Matrix ingress tokens, and `${VAR}` backend headers — not
  just new ones, since a half-compliant loader is worse than one that was
  never started.

## [0.10.0] - 2026-09-21

### Changed
- **BREAKING (behaviour): L3 runs on every input the gateway scans.** L3
  escalated only on model-output provenance, on a suspicious L1 detection, or
  on an L2 score at or above `l3_threshold`. Clean traffic never reached the
  judge — and because L2 *flags* at `l2_threshold` (0.3 in production) while
  escalation needed `l3_threshold` (0.7), there was a band that L2 flagged and
  L3 never reviewed. Gating the semantic judge on the pattern classifier
  agreeing there is something to look at inverts why L3 exists: it is the
  layer built for attacks phrased as ordinary prose, which is exactly what L2
  is documented to miss.

  This was a defensible reading of the "all three layers, full stop" decision
  in c2be892 — that change removed the per-layer `quarantine: false` boolean
  and kept cost control as a threshold. It was not the intended reading. A
  threshold deciding whether a layer executes is an off switch with a dial on
  it. **Cost: every scanned payload now makes an L3 call.**

- **An L3 that cannot run is now reported instead of being silent.** With no
  provider configured, `l3_assessment` was `None` — indistinguishable from
  "ran and found nothing". It now carries `l3_unavailable`, which the warning
  builder already surfaces, the verdict cache already refuses to store (so an
  outage's "clean" cannot outlive the outage), and `block` enforcement already
  refuses on. Closing this was the difference between "L3 always runs" being a
  guarantee and being an aspiration.

- **Trust changes consequence, not execution.** `is_trusted` no longer skips
  L3. It still suppresses the L1 tripwire — a trusted CVE ticket quoting
  attack syntax is the false positive L1 exists to tolerate — but it no longer
  suppresses a judge that read the content and concluded it is an attack.
  Nothing in the tree sets `is_trusted=True`, so this changes no production
  behaviour today.

- **`defense.l3_threshold` is deprecated and ignored.** Retained for one
  release so profiles written for 0.9.x keep loading under `extra="forbid"`;
  setting it logs a warning at load and it is rejected from 0.11.0.

### Added
- `tests/test_l3_always_runs.py` — 26 tests pinning the mandate: every L2
  score below the old threshold reaches L3, no `l3_threshold` value can
  suppress it, the flagged-but-unjudged 0.3–0.7 band is covered explicitly,
  and the gate function's signature is asserted so a new parameter cannot
  become a new way to skip L3 without a test saying why.

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
