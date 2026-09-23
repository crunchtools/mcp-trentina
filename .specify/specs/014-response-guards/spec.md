# Specification: Response Guards

> **Spec ID:** 014-response-guards
> **Status:** Draft
> **Version:** 0.1.0
> **Author:** Scott McCarty
> **Date:** 2026-09-22
> **Ticket:** RT #1500

## Overview

Trentina's gateway can filter a tool call's *arguments* (`parameter_guards`)
and can remove a tool from a profile entirely (`tools_allow` / `tools_deny`).
It has nothing in between: no way to say "this agent may use this tool, but
may not receive these results."

That gap is load-bearing in the live deployment. `agent1` and `agent3` are
internet-isolated Hermes agents; both reach the shared memory backend with
`memory: tools_allow: ["*"]`, which is full read of a corpus that is entirely
work-covered and private. Work IT security policy says that data must not
flow to those agents. `agent2` must keep full access to the same backend.

RT #1500 originally proposed solving this with parameter guards. That cannot
work, and the reason generalizes past this one backend. `check_parameter_guards`
(`gateway/guards.py`) matches globs against named request arguments before the
backend call, and skips any parameter that is absent. Memory recall is
semantic: an agent asks for "my employer's OS roadmap" and the restricted
record comes back in the *response*, with nothing in the request for an
argument-side glob to catch. Guards never see a response body.

## Decision

Add `response_guards` — the same constraint, the same evaluator, applied to
the backend's result.

Trentina is a firewall that inspects what arrives at it. A backend's response
is another inbound payload, and filtering it before relaying is the same
operation the request side already performs. This is generic content-filtering
config, not a memory-specific driver.

### What it is not

A response guard matches literal globs. A backend that paraphrases, encodes,
translates or splits a restricted term passes a guard written for the plain
term. This is accepted, stated in the docs, and is the reason the deny-all
configuration (below) is the strong one: it depends on no vocabulary.

Semantic judgement of content is the defense pipeline's job. The two answer
different questions — "is this hostile?" versus "may this agent receive it at
all?" — and neither substitutes for the other.

## Design

### 1. One evaluator, two applications

The allow/deny loop currently inlined in `check_parameter_guards` is extracted
into `evaluate_constraint(value, constraint) -> str | None`, which both sides
call. `check_parameter_guards` keeps its exact current messages and behaviour;
its existing tests pin that.

`ParameterConstraint` (`gateway/profile.py`, allow/deny globs with the
`GUARD_VALUE_RE` validator) is reused verbatim. No new config primitive.

### 2. Schema — same nesting depth as parameter_guards

```
parameter_guards: dict[tool, dict[param, ParameterConstraint]]   # exists
response_guards:  dict[tool, dict[field, ParameterConstraint]]   # new
```

A request has named parameters; a tool result does not. That is the one place
the two sides genuinely differ, and it is confined to *which string is fed to
the shared evaluator*:

- `field` names a key of the result's `structuredContent`, or
- the reserved name `content`, which matches every text block joined with
  newlines (including an embedded `resource` block's text form).

A missing structured field is skipped, symmetric to the request side's
`value is None: continue`. `content` is always present — the empty string when
a result has no text — so `deny: ["*"]` blocks an empty or purely binary
result too. `fnmatchcase` matches across newlines, so `*NIGHTJAR*` catches the
term anywhere inside a multi-line blob.

### 3. Call site — after the call, before everything else

The check runs in `_route_tools_call`, immediately after the backend returns
and before `_assemble_call_result`. Two properties are deliberate:

**Before reduction.** Pre-processors summarize and paraphrase. A guard reading
the reduced artifact would be matching text a model rewrote, and a forbidden
literal could be dissolved on the way past. The guard reads the bytes the
backend sent.

**Internal backends included.** Internal tools skip reduce and scan because the
firewall already filtered that content at its own ingress. Egress policy is a
different question — it is about who is asking — so the guard runs regardless
of backend type.

One audit row per call: a violation records `DENIED_RESPONSE_GUARD` with the
call's duration *instead of* the `OK` / `TOOL_ERROR` row, not in addition to it.

### 4. Block, never scrub

A violation rejects the whole response, symmetric to request-side
`DENIED_GUARD` rejecting the whole call.

Partial delivery would make the guard a leak oracle: an agent receiving
"everything except what matched" can vary its query to narrow down what
matched. The same reasoning governs the error message, which names the field
and never the content.

The backend was contacted and its call was spent. That is unavoidable — the
restricted material is only identifiable once it exists. What the guard
controls is whether it is relayed.

### 5. Outcome

`DENIED_RESPONSE_GUARD = "denied_response_guard"`, added to `BLOCKED_OUTCOMES`
so a block reads as policy rather than failure in stats. Kept distinct from
`DENIED_GUARD` because the cost profile differs (this one spends the upstream
call) and from `BLOCKED_DEFENSE` because the decision is operator-authored
policy, not a model's risk verdict.

## Applying it to RT #1500

```yaml
memory:
  tools_allow: ["*"]
  response_guards:
    memory_search:
      content: { deny: ["*NIGHTJAR*", "*Nightjar*", "*nightjar*"] }
```

on the `agent1` and `agent3` memory backends; `agent2` is untouched and keeps
full access.

**The honest caveat, recorded here because it shapes the choice:** if every
record in that backend is restricted for those agents, `content: {deny: ["*"]}`
is the correct guard, and cutting the memory read tools from `tools_allow`
achieves the same block with zero code and no wasted upstream call. The generic
mechanism earns its place because the policy need is broader than one backend —
content-pattern egress control for any backend, and defense-in-depth behind an
allowlist — not because it is the cheapest way to close this one hole.

## Files

| File | Change |
|---|---|
| `gateway/guards.py` | Extract `evaluate_constraint`; add `check_response_guards` and the content extractor |
| `gateway/profile.py` | `response_guards` field on `Backend` |
| `gateway/router.py` | Call site in `_route_tools_call`; audit + JSON-RPC error on block |
| `outcomes.py` | `DENIED_RESPONSE_GUARD` + `BLOCKED_OUTCOMES` membership |
| `tools/reload.py` | `_guard_delta` reports response guards, keyed by field |
| `docs/response-guards.md` | New capability page |
| `docs/parameter-guards.md`, `docs/audit-log.md`, `README.md` | Cross-links, outcome table, capability entry |
| `examples/profiles-agent1.yaml` | Worked example on the memory backend |
| `tests/test_gateway_guards.py` | Response-guard unit cases |
| `tests/test_gateway_router.py` | Block short-circuits reduce and scan; audit row; pass-through |
| `tests/test_reload.py` | Delta names fields without echoing patterns |

## Acceptance Criteria

1. A guarded tool whose result matches a `deny` pattern returns a JSON-RPC
   error, delivers no content, and audits `denied_response_guard`.
2. The block short-circuits: neither `reduce_response` nor `scan_tool_response`
   runs.
3. An unmatched result is delivered normally.
4. Error messages name the field and contain no part of the matched content.
5. Existing parameter-guard behaviour and messages are unchanged.
6. A `response_guards` edit appears in the reload diff by field name, with no
   pattern echoed.
7. All six quality gates pass; shipped through the GHA pipeline.

## Architectural Impact

Additive. A backend with no `response_guards` key behaves exactly as before —
the check returns on an empty dict lookup. No migration, no default change.
