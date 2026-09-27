# Specification: Matrix E2EE Termination by Bridge

> **Spec ID:** 015-matrix-bridge
> **Status:** Phases 0–3 shipped (0.44.0, 0.45.0); cutover in progress
> **Version:** 0.1.0
> **Author:** crunchtools
> **Date:** 2026-09-27
> **Ticket:** #162

## Overview

Message bodies in encrypted Matrix rooms are ciphertext at the perimeter. An
injection in a chat message crosses Trentina as an opaque blob and becomes
plaintext inside the agent (`docs/defense-pipeline.md`: "encrypted rooms are
outside what any gateway can defend").

0.18.0 shipped a read-only decryptor that unwraps Megolm if handed a key
(`matrix/keybackup.py`, `preprocess/matrix.py`). In practice it decrypts
almost nothing: a backup's private key is often unrecoverable, some client
libraries cannot upload to key backup at all, and a new agent has no keys to
harvest. Key-harvesting cannot be the design.

**Done is:** Matrix working between two agents with Trentina as the
encryption terminator, reactions and threads intact.

## Decision

Trentina stops sharing a Matrix identity with the agent. Per profile:

```
matrix.org ──(E2EE)──▶ bridge-<profile>   untrusted. Holds the matrix.org login,
                            │              device and crypto store. No credential
                            │              for anything else.
                            ▼  plaintext, one event at a time
                     Trentina gateway     trusted. L1/L2/L3, audit, verdict.
                            │              Sole holder of the appservice token.
                            ▼
                     conduit-<profile>    local homeserver, plaintext,
                            │              agent's internal network, federation off
                            ▼
                          agent
```

Every hard problem of the proxying design (two crypto machines racing for
deliver-once to-device events, lying about `m.room.encryption`, rewriting a
foreign sync stream) came from two programs sharing one identity. This removes
the sharing.

### The trust boundary is a credential split

The bridge runs as its own process (its own container), not a task inside the
gateway. Five credentials exist, split so that no process holds both write paths:

| credential | held by | grants |
|---|---|---|
| matrix.org login, device, crypto store | bridge only | speaking upstream |
| `as_token` | gateway only | writing into the agent's local rooms |
| `hs_token` | gateway and Conduit | authenticating Conduit's pushes to the appservice |
| `ingress_token` | bridge and gateway | the bridge handing plaintext to `/bridge/{profile}/event` |
| `bridge_token` | gateway and bridge | the gateway handing scanned outbound text to the bridge |

The last two are service-to-service and grant nothing on either homeserver. So:

- A compromised bridge can hand the gateway bytes to judge. It cannot deliver
  them, because it has no way to reach Conduit.
- The gateway cannot speak upstream without the bridge, because it has no
  matrix.org credential.

`MatrixBridgeConfig` enforces the gateway's half by shape: it has no field for
a public credential, and `test_no_field_holds_a_public_credential` keeps it
that way. This is what makes verification item 10 a property rather than a
claim. (The plan's earlier wording, "a task alongside the gateway", would have
put both credentials in one process; that is rejected.)

### Where it sits in the driver model

A pre-processor outside the perimeter (`preprocess/base.py`). The bridge
transforms ciphertext into plaintext and judges nothing; everything it emits
crosses `defend()`. Delivery equals what was scanned, so it satisfies
invariant 2 under either reading that file has held.

It feeds a new ingress, `Channel.MATRIX_BRIDGE`, of `Kind.TEXT`: one message's
plaintext. `gateway/drivers.py` is where that is registered and channel-locked.
No processor declares the channel yet, so an empty chain is the only valid
`matrix_bridge.preprocess`; chat messages are far below any minifier's floor.

### The local side is an application service

Trentina registers with each Conduit as an appservice. That gives it:

- **Attribution.** A stand-in local user per remote sender, in the
  appservice's namespace (`@<user_prefix><escaped remote id>:<server_name>`),
  so the agent sees who said what. A bridge that collapsed senders would be
  useless to a security gateway.
- **One writer.** `as_token` is the only write credential into the rooms the
  agent reads, and only the gateway has it.
- **Outbound for free.** Conduit pushes the agent's events to the appservice
  (`hs_token`-authenticated), which is where egress scanning happens.

### Flagged inbound messages

Unlike the `/sync` proxy, the bridge delivers one event at a time, so
withholding a message drops a message rather than the client's sync loop.
`matrix_bridge.enforcement` therefore exists, defaulting to `block`: a flagged
message is replaced in the local room by a `[trentina] withheld` notice that
keeps its relation (reply, thread), the same shape 0.43.0's `/sync`
withholding uses. `flag` delivers it with the warning attached.

### Adopt, don't build

- **Public client:** `matrix-nio[e2e]` 0.26 (ISC). Its e2e extra is built on
  vodozemac, which the `matrix` extra already pins, so one copy resolves. It
  provides the Olm/Megolm machine, key requests and forwarding, device
  tracking, replay detection and Olm unwedging. We add key backup, fallback
  keys, cross-signing and withheld handling.
- **Local homeserver:** Conduit (`famedly/conduit`, v0.10.14 released
  2026-09-26), a single Rust binary with an embedded database. Not
  hand-written: `/sync` semantics are where facades break agents subtly.

## Configuration (phase 0)

```yaml
profiles:
  agent1:
    matrix_bridge:
      enabled: true
      public_user_id: "@agent1:matrix.org"
      bridge_url: http://bridge-agent1:8471  # gateway -> bridge, private host
      bridge_token_env: AGENT1_BRIDGE_TOKEN
      ingress_token_env: AGENT1_BRIDGE_INGRESS   # bridge -> gateway
      enforcement: block
      local:
        homeserver: http://10.0.10.3:6167  # private host
        agent_localpart: agent1
        server_name: agent1.local
        as_token_env: AGENT1_AS_TOKEN
        hs_token_env: AGENT1_HS_TOKEN
        sender_localpart: trentina
        user_prefix: remote_
      preprocess:
        processors: []
```

- Both URLs must be on a private host: loopback, a private address, or a
  single-label container name. A public address or a dotted name is a load
  error. (0.44.0 required loopback; the deployment put the bridge and Conduit
  in separate containers on separate networks, which is the stronger
  boundary, so 0.45.0 relaxed it to private.)
- Tokens travel in `Authorization` headers, never in a path, so no access log
  line holds one.
- Secrets are not resolved while `enabled` is false, so an inert block does not
  demand env vars nothing reads.
- RBAC: an agent-scope reload holds the whole block (`operator_only`). An
  operator reload that moves it reports `restart_required`, since a bridge
  binds its endpoints at startup.

## Conduit deployment layout

One tree per instance, per the constitution's `/srv/<service>/` convention:
`/srv/conduit-<profile>/{config,data}`.

```toml
[global]
server_name = "<profile>.local"
database_backend = "rocksdb"
database_path = "/var/lib/matrix-conduit/"
address = "127.0.0.1"
port = <per-instance>
allow_registration = false
allow_federation = false
allow_check_for_updates = false
trusted_servers = []
```

Provisioning, once per instance: start with a `registration_token`, register
the admin and the agent's local user, register the appservice by posting its
registration YAML to `#admins` (`@conduit:<server_name>: register-appservice`;
Conduit has no config-file path for this), then remove the token. Back up
`data/` and the bridge's crypto store separately: key backup holds Megolm
sessions, not the Olm identity.

## Phasing

Each phase ships behind `enabled: false` and reverts by pointing the agent back
at the old proxy URL, until phase 5 prunes the old devices.

0. **This spec, config models, driver channel, RBAC hold, `nio` extra.** No
   behaviour change. *Shipped in 0.44.0.*
1. **Public client.** Bridge process: login (resume, adopt a mautrix device,
   or password), sync loop, E2EE via nio, parked undecryptables with key
   requests. *Shipped in 0.45.0.*
2. **Inbound.** Remote event → bridge → `/bridge/{profile}/event` →
   `defend_json` → local room as the stand-in sender. Closes the injection
   gap. *Shipped in 0.45.0.*
3. **Outbound.** Agent event → appservice push → `defend_json` → bridge →
   remote. Echo suppression by sender on both sides; replies, threads,
   reactions, edits, redactions. *Shipped in 0.45.0.* Phases 1–3 shipped
   together: the operator accepted agent downtime, and a half-bridge (inbound
   only) leaves the agent unable to answer.
4. **Fidelity and ops.** Membership, room metadata, media, mentions computed
   locally; metrics, `/health`, Nagios.
5. **Escrow and cutover.** Key backup upload, secret storage, cross-signing.
   Migrate both agents, retire `matrix/keybackup.py`, `preprocess/matrix.py`
   and `Kind.DOCUMENT` if nothing else uses it, and prune the agents' old
   devices. Pruning is a security step: afterwards the agent holds no Matrix
   credential of its own, which makes the perimeter mandatory.

## Verification

1. Round trip Element → agent → Element, correct sender, correct thread.
2. Reactions, edits, replies, redactions both ways.
3. No loops, including across a bridge restart mid-flight.
4. Every event the bridge sends upstream is `m.room.encrypted`.
5. An adversarial-corpus payload in a remote message is scanned before it
   reaches the local room, and `block` replaces it with the withheld notice.
6. Late keys: an event that arrives before its key is relayed once the key
   lands, not dropped.
7. Restart survival: same device, no fresh identity upload, no duplicates.
8. Disaster recovery: backup plus account restores; backup alone fails as
   documented.
9. Conduit unreachable off-box, federation off, per instance.
10. The bridge cannot deliver: it holds no credential but matrix.org, and a
    message it emits reaches the agent only after a recorded verdict.
11. Instance isolation: one bridge cannot read another's store or rooms.
12. RBAC: an agent reload cannot move `matrix_bridge`. *Tested in phase 0.*
13. Anti-skip guard: CI fails if `nio.crypto` is missing. *Added in phase 0.*
14. Staging first: scratch room and throwaway account, then one agent, then
    the other.
15. Full gates: ruff, mypy, pytest 3.11–3.14, Gourmand, locked `uv.lock`, GHA
    image build.

## Prerequisites from the operator

- One Matrix login per agent for the bridge to own (phase 1), plus a throwaway
  account for staging.
- A route through user-interactive auth for each account (its password, in
  practice): cross-signing upload and device deletion both require it, and a
  bare access token cannot satisfy it (phase 5).
- Phase 5: backfill history into the local rooms, or start clean.

## Risks

- Trentina becomes the critical path for message delivery.
- Bridge bookkeeping (room/user mapping, echo suppression, transaction ids) is
  where bridges historically bite.
- Losing the crypto store is not recoverable from key backup alone.
- Push rules cannot read ciphertext upstream, so mention counts and
  server-side search do not work on the public side.
