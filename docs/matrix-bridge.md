# Matrix Bridge

Encrypted Matrix rooms are ciphertext at the perimeter, so a gateway that only
proxies `/sync` cannot read what it forwards. The bridge terminates the
encryption instead: Trentina's bridge process is the agent's Matrix client
upstream, and the agent talks plaintext to its own homeserver. Every message
crosses L1 ∥ L2 → L3 in both directions. Design and rationale: spec 015
(`.specify/specs/015-matrix-bridge/spec.md`), issue #162.

```
matrix.org ⇄ bridge-<profile>    network: egress only    holds the upstream login + crypto store
                 ⇅ HTTP, two tokens
             Trentina gateway     both networks           judges every event, sole writer below
                 ⇅ appservice (as_token / hs_token)
             conduit-<profile>    agent's internal net    plaintext, federation off
                 ⇅
               agent              agent's internal net
```

The bridge shares no network with Conduit and holds no token for it, so it
cannot deliver anything on its own. The gateway holds no upstream credential,
so it cannot speak to matrix.org without the bridge.

## Gateway: the `matrix_bridge` profile block

```yaml
profiles:
  agent1:
    auth:
      bearer_token_env: AGENT1_TOKEN
    matrix_bridge:
      enabled: true
      public_user_id: "@agent1-bot:matrix.org"   # the identity the bridge speaks as
      bridge_url: http://bridge-agent1:8471       # private host only
      # gateway -> bridge, then bridge -> gateway
      bridge_token_env: AGENT1_BRIDGE_TOKEN
      ingress_token_env: AGENT1_BRIDGE_INGRESS
      enforcement: block                          # or flag
      local:
        homeserver: http://10.0.10.3:6167        # private host only
        server_name: agent1.local
        agent_localpart: agent1                   # the agent's user on Conduit
        as_token_env: AGENT1_AS_TOKEN
        hs_token_env: AGENT1_HS_TOKEN
        sender_localpart: trentina                # the appservice's own user
        user_prefix: remote_                      # stand-ins for remote senders
```

Hosts must be loopback, a private address, or a single-label container name.
The four tokens are resolved (with `_FILE` support) only when `enabled`. Every
field is operator-only: an agent-scope `reload_profiles` holds the block, and
an operator reload reports that a restart applies it.

**Inbound**, each message, reaction and sticker is judged together with its
sender's display name and the room's name and topic. A redaction is mirrored
without being judged, because it carries nothing across: its reason text is
dropped, and it only removes an event that was judged when it arrived. Under `block` a flagged or incompletely judged event becomes a
`[trentina] withheld: <reason>` notice from the appservice bot, keeping its
thread or reply; a withheld reaction is dropped. Under `flag` it is delivered
with `_trentina_warning` in its content. **Outbound**, only the agent's own
events are carried; a refused one is not sent, and the agent gets a notice.

Local rooms exist before anyone speaks in them. The bridge announces every
room it is in when it starts, and each room it joins later; the gateway judges
the room's name and topic, creates the local room, invites the agent, and
holds the announcement up to 30 seconds for the agent to join, so the room's
first messages are not written before the agent can read them. An agent that
has not joined by then does not stall the bridge: the room is used anyway,
and the delay is logged.

A direct message is a true DM: its local room is created by the other
person's stand-in and holds exactly two members, the stand-in and the agent.
Agents tell a DM from a group by member count, and a group is where they
answer only when mentioned. A DM made by 0.45.0, with the appservice bot in
it, is handed over on the bridge's next start.

Remote senders appear as stand-ins, `@<user_prefix><escaped id>:<server_name>`,
where the escape is the spec's mapping (`@Scott_M:matrix.org` →
`@remote__scott___m=3amatrix.org:agent1.local`). The agent's own remote ID is
rewritten to its local ID inbound and back outbound, so mention detection still
works. The agent's allowlists must name the stand-ins and the appservice bot.

Endpoints, on the gateway's port:

| path | caller | auth |
|---|---|---|
| `POST /bridge/{profile}/event` | bridge process | `Bearer` ingress token |
| `PUT /bridge/as/{profile}/_matrix/app/v1/transactions/{txn}` | Conduit | `hs_token` |

Mapping state (rooms, stand-ins, event IDs, dedupe) is
`bridge-<profile>.db` beside the blocklist. Losing it costs duplicated rooms,
not a breach.

## Bridge process

Same image, its own container, on the egress network only:

```
python -m mcp_trentina_crunchtools.bridge.main run
```

| variable | meaning |
|---|---|
| `BRIDGE_PROFILE` | the gateway profile this bridge serves (required) |
| `BRIDGE_USER_ID` | upstream Matrix user (required) |
| `BRIDGE_HOMESERVER` | upstream base URL (default `https://matrix-client.matrix.org`) |
| `BRIDGE_GATEWAY_URL` | gateway base URL, e.g. `http://mcp-trentina:8019` (required) |
| `BRIDGE_INGRESS_TOKEN` | presented to the gateway; the profile's `ingress_token_env` value (required) |
| `BRIDGE_TOKEN` | required of the gateway; the profile's `bridge_token_env` value (required) |
| `BRIDGE_PICKLE_KEY` | encrypts the crypto store at rest (required) |
| `BRIDGE_STORE_DIR` | crypto store, session, sync position (default `/data`) |
| `BRIDGE_LISTEN_HOST` / `BRIDGE_LISTEN_PORT` | API bind (default `127.0.0.1:8471`; set `0.0.0.0` in a container) |
| `BRIDGE_DEVICE_ID` + `BRIDGE_ACCESS_TOKEN` | adopt an existing device |
| `BRIDGE_PASSWORD` | log in a new device (first boot only) |
| `BRIDGE_OLD_ACCESS_TOKEN` | `logout-device` only: the token of the device to prune |
| `BRIDGE_RECOVERY_KEY` | `sign-device` only: the account's secret-storage recovery key |
| `BRIDGE_DEVICE_NAME` | name for a new device (default `Trentina bridge`) |
| `BRIDGE_LOG_LEVEL` | default `WARNING` |

Every secret also reads from `<NAME>_FILE`. After the first start the session
in `BRIDGE_STORE_DIR/session.json` wins over the environment.

The first sync only establishes position; history is not replayed. The sync
position is written only after every event in the batch has been answered by
the gateway: taken, or refused for good. A 5xx, a connection failure, a 401,
403 or 429 is retried until it succeeds, since those are the gateway's state
rather than the event's; any other 4xx (a malformed or oversized event) is
logged at ERROR and dropped, so one bad event cannot stall the room. Events whose keys have not arrived are parked (`pending.json`), their
keys requested, and after ten minutes forwarded as a
`[trentina] could not be decrypted` notice.

### Adopting a mautrix device

A device already in use keeps its identity and the room keys it holds, and
needs no password. Stop the agent for good first: two processes driving one
Olm account diverge immediately.

```
python -m mcp_trentina_crunchtools.bridge.main import-mautrix --crypto-db /import/crypto.db
```

Then start the bridge with `BRIDGE_DEVICE_ID` and `BRIDGE_ACCESS_TOKEN` set to
the agent's.

### Pruning the old device

```
python -m mcp_trentina_crunchtools.bridge.main logout-device
```

With `BRIDGE_OLD_ACCESS_TOKEN` set to the agent's old token, for this run
only. A homeserver behind MAS serves neither `/delete_devices` nor `DELETE /devices`;
logging a device out with its own token removes it. Afterwards the agent holds
no upstream credential, which is what makes the perimeter mandatory.

### Verifying a new device

A device the bridge logged in fresh is unsigned, and clients show it as
unverified. An adopted device is usually signed already.

```
python -m mcp_trentina_crunchtools.bridge.main sign-device
```

With `BRIDGE_RECOVERY_KEY` set to the account's recovery key, for this run
only. It reads the self-signing key from secret storage, checks it against
the published key, and signs the bridge's device, but only if the
homeserver's copy of the device's keys is exactly what the bridge's own crypto
store holds. No identity is reset, so nobody has to re-verify the account.

A recovery key opens only the secret storage it was made with. If storage was
set up again since, the old key is refused, and if nobody holds the current
one the self-signing key cannot be read at all. Then:

```
python -m mcp_trentina_crunchtools.bridge.main reset-identity
```

It generates new cross-signing keys, stores them in new secret storage, and
prints the new recovery key once, before anything is published. Keep it. Then
it uploads the identity; a homeserver behind MAS first asks the account owner
to approve the reset, so the command prints a link, to be opened while logged
in as the account, and waits up to ten minutes. Last, it signs the bridge's
device. If that step fails, `sign-device` with the printed key finishes it; if
the reset is never approved, nothing was published and a rerun replaces the
stored keys. Everyone who had verified the account sees its identity change and
verifies it again.

## Conduit

One per profile, on the agent's internal network only:

```toml
[global]
server_name = "agent1.local"
database_backend = "rocksdb"
database_path = "/var/lib/matrix-conduit/"
address = "0.0.0.0"
port = 6167
allow_registration = false
allow_federation = false
allow_check_for_updates = false
trusted_servers = []
```

Conduit registers appservices from its admin room, not from a file. Once,
with a temporary `registration_token`: register the admin user (it joins
`#admins`), register the agent's user, then post

    @conduit:agent1.local: register-appservice
    ```
    id: trentina
    url: http://<gateway ip on this network>:8019/bridge/as/agent1
    as_token: <AGENT1_AS_TOKEN>
    hs_token: <AGENT1_HS_TOKEN>
    sender_localpart: trentina
    rate_limited: false
    namespaces:
      users:
        - exclusive: true
          regex: '@remote_.*:agent1\.local'
      aliases: []
      rooms: []
    ```

and remove the registration token.
