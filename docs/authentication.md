# Authentication

Trentina supports four ways for a client to prove who it is. They are not
alternatives to pick once for the gateway — each is set per profile, so one
gateway can serve an agent over a static token, a desktop MCP client over
dynamic registration, and a vendor connector over an external identity
provider, all at the same time.

Authentication answers "who is this". Authorization — "may they use this
profile" — is always `allowed_emails` in the OAuth modes, and possession of the
token in the static one.

## Choosing one

| Mechanism | Who mints the token | Client must support | Trentina's role | Use it for |
|---|---|---|---|---|
| **Static bearer** | You | Sending a header | Resource server with a shared secret | Agents you control — kagetora, takeda, scripts |
| **OAuth proxy + DCR** | Trentina, proxying login to Google | Dynamic client registration | Authorization server **and** resource server | Claude Code and most MCP clients |
| **OAuth proxy + provisioned client** | Trentina | A pasted Client ID and Secret | Authorization server + resource server | A console-configured connector willing to use our AS |
| **Delegated issuer** | Google (or another IdP) directly | Linking to that IdP itself | Pure resource server | A connector that refuses a third-party AS — gemini.google.com Custom Apps |

Two quick tests. If the client can send an `Authorization` header you choose,
use a static bearer and stop. If it cannot, and it can register itself, use the
proxy — nothing to configure beyond the allowlist.

## Static bearer

The default, and still checked first on every request regardless of what else
a profile enables.

```yaml
profiles:
  kagetora:
    auth:
      bearer_token_env: TRENTINA_PROFILE_KAGETORA_TOKEN
```

The token value lives in an environment variable, never in `profiles.yaml`.
The client sends `Authorization: Bearer <token>`; a miss falls through to the
profile's OAuth path if it has one, otherwise 401.

Because it is checked first, it short-circuits before any outbound verification
call — which is also why a profile with both mechanisms carries **two
independent credentials**. That is intended, and worth remembering when you
rotate one and not the other.

## OAuth proxy + dynamic client registration

Trentina acts as an OAuth authorization server and proxies the actual login to
Google. A client discovers the AS from the profile's RFC 9728 document, registers
itself at `/register`, and is sent through `/authorize` → Google → `/token`.

```yaml
profiles:
  josui:
    auth:
      bearer_token_env: TRENTINA_PROFILE_JOSUI_TOKEN
    oauth:
      enabled: true
      allowed_emails:
        - scott@example.com
```

```bash
TRENTINA_OAUTH_GOOGLE_CLIENT_ID=...        # required when any profile proxies
TRENTINA_OAUTH_GOOGLE_CLIENT_SECRET=...
TRENTINA_OAUTH_BASE_URL=https://mcp.crunchtools.com
TRENTINA_OAUTH_JWT_SIGNING_KEY=...         # pin it so issued tokens and client
                                           # registrations survive a secret rotation
```

`enabled: true` requires a non-empty `allowed_emails`; a seat open to any Google
account fails validation. Set `FASTMCP_HOME=/data/fastmcp` so registrations
persist across a restart.

Endpoints mounted: `/authorize`, `/token`, `/register`, `/consent`,
`/auth/callback`, and a root `/.well-known/oauth-authorization-server`.

**Failure mode.** A client that reports "automatic registration failed" without
ever POSTing to `/register` is reading the discovery documents and rejecting
them — historically an issuer that did not match byte-for-byte (0.8.1) or a CIMD
flag the proxy advertised but did not implement (0.8.2).

## OAuth proxy + provisioned confidential client

Same as above, but for a connector that will not register itself and instead
makes an operator paste credentials. Trentina issues no secret of its own, so
you declare one.

```yaml
    oauth:
      enabled: true
      allowed_emails: [scott@example.com]
      client_id: 375f3fdb-c322-41bc-8dc6-c2010a095f04
      client_secret_env: TRENTINA_GEMINI_APP_CLIENT_SECRET
      client_redirect_uris:
        - https://connector.example.com/oauth/callback
```

All three keys are required together, and the secret is named by environment
variable rather than written in the file. Redirect URIs are matched **verbatim**
— none of the pattern widening DCR clients get for unpredictable localhost ports.

With such a client declared, the authorization-server metadata advertises
`client_secret_post` alongside `none`, and the secret is genuinely verified on
every `/token` call.

## Delegated issuer

Trentina stops being an authorization server for the profile. It names an
external one in the profile's RFC 9728 document, the client authenticates there
directly, and Trentina verifies the token that comes back.

```yaml
    oauth:
      enabled: true
      allowed_emails: [scott@example.com]
      issuer: https://accounts.google.com
      audience_env: TRENTINA_GEMINI_GOOGLE_CLIENT_ID
```

You create the OAuth client in the **Google Cloud console**, put its Client ID
and Secret into the connector's form, and give Trentina only the Client ID via
`audience_env`. Trentina never sees the secret.

No `/authorize`, `/token` or `/register` is mounted for this profile. If every
OAuth profile delegates, none is mounted at all and the upstream
`TRENTINA_OAUTH_GOOGLE_CLIENT_ID`/`_CLIENT_SECRET` are not required.

### Why this exists

gemini.google.com Custom Apps offers exactly three fields — MCP server URL,
Client ID, Client Secret — and no authorization or token URL. It reads our
protected-resource document, finds Trentina named as the authorization server,
and refuses to perform a token exchange against an AS it has no relationship
with. In live captures `/authorize`, `/consent` and `/auth/callback` all
completed, we minted a client code and redirected with a verbatim `state` and a
byte-correct RFC 9207 `iss`, Google fetched both discovery documents
server-side — and `POST /token` was never issued. Not once.

That is the signature of this problem: the browser half of the flow succeeds
completely and the token exchange never happens.

### Security rules

These are enforced at load, not merely advised.

**The audience is the security boundary.** A Google access token verifies for
*any* OAuth client unless its `aud` is pinned. Without `audience_env`, every
third-party app an allowlisted human ever authorized would hold a working
credential for the profile, carrying the same verified email the allowlist
checks. `issuer` therefore requires `audience_env`.

**Give that Google client exactly one redirect URI.** A Web-application client
permits the implicit flow, so a second URI — a localhost one added for testing
is the classic mistake — lets anyone mint a token with your `aud` for their own
Google account, leaving only the allowlist in the way.

**One Google client per profile.** Google supports no RFC 8707 resource
indicator, so the token binds to the client ID rather than to the resource URL.
Two profiles sharing an audience accept each other's tokens; a delegated
audience equal to `TRENTINA_OAUTH_GOOGLE_CLIENT_ID` would accept every upstream
token the proxy holds. Both are refused at startup.

**Delegated and provisioned are mutually exclusive.** The provisioned fields
register a client against *our* authorization server, which a delegated profile
does not run. Combined, that credential would be registered into the shared
proxy and become a live client for the other profiles' AS.

**`role: operator` on a delegated profile** hands the gateway admin tools to
whoever is on its allowlist. The gateway warns at startup.

### What a restart is needed for

`issuer` and `audience_env` are read once at startup and bound into the route
closures, like `llm_providers`. `reload_profiles` reports them as unapplied
rather than claiming success. `allowed_emails` is read per request and does
apply live — which is the one key you are likely to edit under pressure.

### Verification, precisely

Google's tokeninfo endpoint is **not** RFC 7662 introspection: it is a GET-style
endpoint with no resource-server authentication. Trentina sends the token in a
POST body rather than the query string Google documents, because HTTP clients
log request URLs and that would write live bearer tokens into the journal.

Rejections Google pronounced are cached briefly so an unauthenticated flood
cannot be turned into an equal flood against Google's quota. Rejections caused
by Google being *unreachable* are never cached — that would turn an outage into
a lockout. Valid tokens are never cached at all, so a revoked token stops
working on the very next request.

## Related

- [Per-Agent Profiles](profiles.md) — the full profile schema
- [MCP Gateway](gateway.md) — routing and namespacing
