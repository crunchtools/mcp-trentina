---
name: trentina-boundary-review
description: Strict review of Trentina's trust boundary and fail-closed correctness. Treats every boundary crossing as a proof obligation, classifies every premise by authority tier, rejects named anti-justifications, and reports findings with file:line, the obligation violated, tier evidence, a failure scenario and a severity.
argument-hint: "[diff range, file paths, or PR number; default: the working-tree diff against main]"
allowed-tools: Read, Grep, Glob, Bash
---

# Trentina Boundary Review

## Mission

Act as an extremely strict reviewer of the code that decides what crosses
Trentina's trust boundary. Trentina is a security perimeter: every agent on the
gateway trusts that a fetch fails closed, that a verdict is not lying, that a
denial is audited, and that nothing one profile does can be read by another.
The goal is not reassuring prose. The goal is that a maintainer can take each
claim in the code, translate it into an obligation, and check that obligation
against a named source.

The governing standard:

> Every boundary crossing creates proof obligations, and the code at the
> crossing must locally show that each one is discharged, or say in a
> `# TRUST:` comment which named invariant discharges it.

Python has no `unsafe` keyword, so the surface is defined by what the code
does, not by syntax. That is the Activation list below. A reviewer that finds
nothing wrong says so; a reviewer that flags everything gets turned off.
Precision is graded as hard as recall (see Precision discipline).

## Activation criteria

Apply this skill to any change, file or function that does one of these. The
first ten are from #90; the last five are the channels the #90 audit found.

1. Returns content originating outside the trust boundary to a model or a
   caller: a fetched page, a file, a backend `call_result`, an ingress payload,
   a Matrix event, an LLM completion.
2. Decides whether content is safe: `l1/`, `quarantine/` (`classifier.py` is
   L2, `agent.py` is L3), `defense.py`, `modes.py`, `gateway/ingress_defense.py`,
   `gateway/guards.py`.
3. Can turn a fail-closed path into a fail-open one: a bare or broad `except`,
   a broad `try` around a defense call, a default return of `BENIGN`, `ok`,
   `True`, `None`-as-clean, or an empty verdict.
4. Truncates, caps, samples, heads, selects or short-circuits before a scan
   completes (`classifier.head`, `admission`, pre-processors, `selection.py`).
5. Returns early and skips the audit row (`router._audit`), the blocklist write,
   the detection record, or the D-Bus event.
6. Crosses the async boundary: sync work in a coroutine (`classify()` instead of
   `classify_async`), blocking I/O or `getaddrinfo` on the event loop, a bare
   `provider.generate` instead of `limited_generate`.
7. Deserializes or executes: `pickle`, `yaml.load` without `SafeLoader`, `eval`,
   `exec`, `subprocess`, `__import__`, `importlib`, template rendering.
8. Builds a filesystem path, SQL statement or URL from caller-influenced input.
9. Runs a regex over attacker-controlled input (ReDoS is a liveness attack on
   every agent behind the gateway), or evaluates a backend-supplied `pattern`.
10. Parses a backend's MCP response, a tool schema, `profiles.yaml`, or the
    environment.
11. Writes shared state without a profile key: a SQLite table, a module-level
    dict or cache, a circuit breaker, a counter, anything one profile writes
    and another can observe through any tool result, refusal, count or timing.
12. Lets a caller-chosen string reach a log record: a URL, path, query,
    argument name, header, backend or provider error text, Matrix id, or an
    exception's message (`logger.exception`, `exc_info`, `%s` of `exc`).
13. Sends a request to a URL without `egress.open_guarded` / `egress.check_url`:
    any `httpx.AsyncClient`, `httpx.get`, `urllib`, socket, or
    `follow_redirects=True`.
14. Passes through a gateway-reserved key from a backend or ingress payload:
    `_trentina_warning`, `_trentina_refusal`, `scan`, or any `_trentina_*`,
    at the top level or nested in `structuredContent`.
15. Opens, stats, lists or resolves a filesystem path that did not come
    through `tools/confine.py` (`confine`, `open_confined`).

Use the strictest reasonable reading. When two rules conflict, choose the more
demanding one unless it contradicts a Tier 1 axiom.

## Core model

### Docstrings and project docs are lemmas

A docstring that says "never raises on a detection", "refusals name nothing",
or "every path here is audited" is a claim of Tier 3 authority. The code under
it must prove it on every path, including every exception path. The #87 audit
bug was found exactly this way: `docs/audit-log.md` claimed every call was
recorded, and two denial paths returned before `_audit`.

### `# TRUST:` comments are proofs

A `# TRUST:` comment at a boundary crossing is the author's claim that the
obligations at that point are discharged. Review it the way you would review a
proof: each premise must be classified, and each must still hold at that
program point.

### The target

The boundary is sound only if no caller of a gateway tool, using the tools as
offered in adversarial but schema-valid ways, can:

- receive untrusted content that no layer fully judged, without a warning its
  mode promises;
- cause a defense failure to be delivered or recorded as a clean result;
- make the gateway fetch, read or log something the policy forbids;
- send a bit to, or receive a bit from, another profile through gateway state;
- stall the event loop that every other profile shares.

A logic bug that fails closed (refuses too much, audits an error) is a defect
but not a boundary defect. Grade it `low` at most.

## Authority and evidence hierarchy

Every premise in a finding, or in a `# TRUST:` comment, must come from one of
four tiers. Cite the tier.

### Tier 1: Axioms

The Python Language Reference and the CPython standard-library documentation.
Claims about exception semantics (what `except Exception` does and does not
catch; `BaseException`, `CancelledError`), generator and coroutine behavior,
what blocks the event loop, `re` backtracking, dict ordering, encoding,
`os.open` flags, `socket.getaddrinfo`, `ipaddress` properties, and `sqlite3`
parameter binding bottom out here.

### Tier 2: Trusted dependency contracts

What `httpx`, `httpcore`, `onnxruntime`, `transformers`, `fastmcp`, `mcp`,
`pydantic`, `pyyaml` and `uvicorn` DOCUMENT. Not what they happen to do in the
installed version. Examples: httpx documents that `follow_redirects=True`
follows `Location` without consulting the caller; pydantic documents that
`extra="forbid"` refuses unknown keys; `yaml.safe_load` documents that it
builds only plain types.

### Tier 3: Project-local invariants

`docs/defense-pipeline.md` (rules P1-P10), `docs/gateway-design.md`,
`docs/parameter-guards.md`, `docs/audit-log.md`, `docs/blocklist.md`,
`docs/profiles.md`, `SECURITY.md`, `CLAUDE.md`, and module docstrings that
state a contract (`egress.py`, `logsafe.py`, `tools/confine.py`,
`tools/judged.py`, `outcomes.py`). These are lemmas, not self-proving. A
finding may cite one only after checking that the code establishes it on every
path. Reviewing code against them is how you find the places where the doc is
the thing that is wrong. When code and doc disagree, report it: the finding
names both locations and says which one is right.

### Tier 4: Local facts

What is provably true at that program point: a branch just taken, a value just
validated, a type the checker enforces, no intervening `await` that could let
shared state change, no callback into caller code. A local fact is valid only
if still true where it is used. An `await` between a check and a use
invalidates any fact about shared state.

### Not axioms

None of these is evidence. A premise that rests on one is UNPROVED.

- "CPython does X" or "the current httpx does X" (only documented behavior is
  Tier 2).
- "The tests pass", "CI is green", "it worked in production".
- "The classifier is pretty good at that", "L3 would catch it".
- "An attacker wouldn't bother", "nobody would send that".
- "The agent is ours" or "the agent is well-behaved". Agents are the adversary
  model: the incident behind #90 was 1,200 agents that were supposed to be
  isolated.
- "The operator wrote that config" for any value a caller can influence.
- Comments, commit messages, PR descriptions and issue threads, unless the
  claim is also in a Tier 3 document the code is checked against.

## Mandatory fact classification

Every proof-relevant sentence in a finding or a `# TRUST:` comment must be
classifiable as one of:

- `T1 AXIOM`: Python reference or stdlib docs.
- `T2 DEPENDENCY`: a documented contract of a listed dependency.
- `T3 INVARIANT`: a named project document or contract docstring, verified
  against the code.
- `T4 LOCAL`: a visible check, branch, type or control-flow fact at this point.

Reject any unclassified premise. The labels need not be written on every
sentence, but "where does this fact come from?" must have an immediate answer.

## Obligations

Findings name the obligation they violate by code. The eval grades on these.

| Code | Obligation |
|---|---|
| O1 FAIL-CLOSED | A failure, exception, timeout or absence in a judging layer never yields a benign verdict, a delivered payload in block/redact, or a missing refusal. |
| O2 COMPLETE-READ | Nothing is reported clean that was not read whole. A partial read is either refused (block, redact) or delivered with the truncation stated (flag). |
| O3 AUDIT-EVERY-EXIT | Every exit from a tool-call path writes exactly one audit row, including denials, guard refusals and exceptions. |
| O4 OUTCOME-FIDELITY | The recorded outcome says what happened: a defense block is not an error, a backend `isError` is not success, a denial is not absent. No boolean collapse. |
| O5 LIVENESS | No blocking work on the event loop; no super-linear regex over attacker input; bounded memory, time and concurrency per caller. |
| O6 EGRESS | Every outbound request goes through `egress.open_guarded` or `egress.check_url`, is decided on the resolved address, and checks every redirect hop. |
| O7 CONFINEMENT | Every caller-supplied filesystem path goes through `tools/confine.py` before any `open`, `stat`, `scandir` or `resolve` that returns data. |
| O8 LOG-HYGIENE | No caller-chosen string, and no exception message that may carry one, reaches a log record. |
| O9 PROFILE-ISOLATION | State written on behalf of one profile is either keyed by profile or yields no observable signal to another profile: no bit, timestamp, count, or refusal difference. |
| O10 TRUST-MARKERS | Gateway-reserved keys arriving from a backend or ingress are stripped before the gateway adds its own. |
| O11 NO-EXECUTION | Untrusted bytes are never deserialized into objects, evaluated, executed, imported, or used as a template, include or path. |
| O12 CLOSED-OUTPUT | Text returned to an agent on refusal or error is a closed set: reason codes, `FINDING_TYPES`, never L3 prose, backend error text, a path or an address. |
| O13 DOC-AGREEMENT | A Tier 3 claim the code contradicts. Name both sides. |

## The `# TRUST:` convention

Every boundary crossing in the Activation list carries a `# TRUST:` comment
immediately above the crossing (or in the docstring of a function that is
wholly a crossing). Keep it to eight lines, Gourmand's comment-block limit:
it replaces the prose comment it would otherwise sit beside. Format:

```text
# TRUST: <one-line statement of the crossing>
#   untrusted: <what is untrusted here, and who chose it>
#   judged-by: <the layer, guard or function that checked it, or "none: <why>">
#   on-failure: fail-closed (<what the caller gets>) | proceed-with-warning (<why that is acceptable FOR THIS TOOL, with the T3 source>)
#   owner: <the module or function that holds the obligation>
#   evidence: <tier-labelled premises, e.g. T2 httpx docs ..., T3 docs/defense-pipeline.md P4, T4 branch at :NN>
```

The `safe_*`/block versus `quarantine_*`/flag split that #90 describes is
exactly a difference in `on-failure`, and should read that way.

### Worked example 1: bookkeeping failure keeps the verdict (`src/mcp_trentina_crunchtools/defense.py`, in `defend`)

```python
    if flagged_by is not None and record:
        # TRUST: detection bookkeeping after the verdict exists
        #   untrusted: `source`, the caller's URL or path, reaches the row and the log
        #   judged-by: nothing needed; the verdict above is final
        #   on-failure: fail-closed on the verdict: a failed SQLite write or D-Bus emit
        #     is an audit gap to alarm on, never a reason to lose flagged_by
        #   owner: defense.defend
        #   evidence: T3 docstring "never raises on a detection"; T3 #262 logging rule;
        #     T1 `except Exception` leaves CancelledError to propagate
        try:
            ...
        except Exception as exc:
            logger.error(
                "defense: failed to record detection for %s (verdict kept): %s at %s",
                redact_source(source), exc_kind(exc), exc_where(exc),
            )
```

This `except Exception` is correct. It does not return a verdict; it keeps one
that already exists. Contrast the reject pattern "we catch the exception and
log it", where the `except` is what produces the verdict.

### Worked example 2: a connection the guard never checked (`src/mcp_trentina_crunchtools/egress.py`, `PinnedBackend.connect_tcp`)

```python
        addresses = self._pins.get((host, port))
        if not addresses:
            # TRUST: dialling a (host, port) for an outbound fetch
            #   untrusted: host and port, from the agent's URL or a redirect Location
            #   judged-by: egress.check_url, which pins every address it admitted
            #   on-failure: fail-closed; a request the loop never checked is refused
            #   owner: egress.open_guarded
            #   evidence: T3 module docstring; T4 open_guarded pins before every send;
            #     T2 httpcore sends the URL host as server_hostname, so TLS checks the name
            raise EgressRefusedError("unresolvable")
```

Both comments are in the source at those locations.

## Review procedure

### Phase 1: Scope

#### Step 1: Collect the change

Read the target the caller named. With no target, review
`git diff main...HEAD` plus the working tree. Read every changed function
whole, and its callers one level up, because an obligation is often
discharged (or not) by the caller.

#### Step 2: Mark the crossings

List each place in scope that matches an Activation item, with its number.
Code that matches none is out of scope; say so and stop there for that code.

**Do NOT proceed to Phase 2 until every crossing in scope is listed.**

### Phase 2: Prove or refute

#### Step 3: State the obligations

For each crossing, write the obligations (by code) it creates.

#### Step 4: Find the premises

For each obligation, find what discharges it: a `# TRUST:` comment, a Tier 3
contract, a local check. Classify each premise by tier. Walk every exit:
`return`, `raise`, `yield`, the fall-through, and each `except` arm.

#### Step 5: Verdict

Give each obligation one verdict:

- `PROVED`: every premise is classified and still holds at the crossing.
- `UNPROVED`: no counterexample found, but a premise is missing, unclassified,
  or rests on a non-axiom. Missing `# TRUST:` on a crossing is UNPROVED, never
  worse than `low` by itself.
- `UNSOUND`: a concrete input or sequence of calls violates it. Every UNSOUND
  finding carries a scenario.

**Do NOT report an UNSOUND finding without a concrete failure scenario.**

### Phase 3: Report

#### Step 6: Findings

Use the output format below. Order by severity. End with the list of
crossings you marked PROVED, one line each, so the reader can see what was
checked and passed.

## Reject patterns

Refuse each of these on sight as a justification. Each names what to require
instead.

### R1. "We catch the exception and log it"

Where the caller cannot tell a block from a backend failure, or where the
`except` arm produces the verdict. Require the exception to become a refusal
the caller sees and an audit row with the right outcome (O1, O4).

### R2. "Returns True because nothing raised"

`success = True` unless something raised is how #87 recorded fail-closed
blocks as errors, backend `isError` as success, and denials not at all.
Require an outcome derived from what happened (O4).

### R3. "The classifier didn't flag it"

For content the classifier never fully read. A truncated, sampled or headed
scan is not a clean scan. Require refusal, or a warning stating the truncation
where the mode's contract promises one (O2).

### R4. "The sanitizer already handled that"

With no named stage and no test. L1 counts and normalizes a copy; it makes
nothing safe (CLAUDE.md, `l1/`). Require the stage by name and the test that
pins it.

### R5. "This path is internal"

For anything reachable from a gateway consumer, directly or through a tool
another backend offers. Require the reachability argument, tier-labelled.

### R6. "It's the same logic as the other path"

Two copies drift (`tools/judged.py` history; PR #89; the two JSON walks before
#167). Require one path, or a test that proves the copies agree.

### R7. "Config makes this safe"

A default-off guard is not a guard. Require the default to be the safe value,
and an off switch to warn at startup.

### R8. "The model will notice"

A downstream LLM is never a control. Neither is `_trentina_warning` against a
convincing injection. Require a mechanical control.

### R9. "The agent can't see that anyway"

Said of a shared store, a log, a cache, or a counter. Agents hold
`journal_query`, `container_logs`, `quarantine_stats`, `cache_flush`, and every
refusal an agent receives. If one profile can write it and another can observe
any consequence of it, it is a channel (O8, O9). Require a profile key, or
proof that no tool result, refusal, count or timing depends on it.

### R10. "It's only one bit"

One bit per call is a channel. The #90 audit measured `cache_flush` at about
10 bit/s and the blocklist at one bit plus a timestamp per URL, persistent
across sessions. Require zero bits, or a written residual with a rate bound
(as #263 does for the circuit breaker).

### R11. "The operator wrote that config, so it's trusted"

True for a value the operator chose. False for one a caller can influence:
a backend's tool schema and its `pattern`, a tool name the backend announces,
a URL assembled from an argument, a `profiles.yaml` edit an agent applies
through `reload_profiles`. Require the provenance of the specific value.

### R12. "The refusal message is harmless"

When refusals differ by hidden state, they form an oracle: `on the blocklist
since {detected_at}` tells a second profile what the first one fetched and
when; "not in profile" versus "unknown backend" tells it what exists.
Require refusals that are identical across the hidden state (O9, O12).

### R13. "It's just a cache"

State one profile can write and another can read is a message board unless it
is keyed by profile. That includes timestamps and counts (O9).

### R14. "The agent picked the URL"

That is the problem, not the excuse. Require every hop checked against the
resolved address (O6).

### R15. "The verdict is in the payload"

A trust marker that arrives in-band is forged until the gateway strips the
inbound key and sets its own (O10).

### R16. "It's local, not remote"

A parser given attacker bytes must not resolve templates, includes, entities
or paths; a local file read is SSRF by other means once remote is blocked (O7,
O11).

## Output format

Return findings as a JSON object, then (for a human reader) the same findings
as a table. The JSON is what CI grades.

```json
{
  "findings": [
    {
      "file": "src/mcp_trentina_crunchtools/tools/fetch.py",
      "line": 212,
      "obligation": "O9",
      "verdict": "UNSOUND",
      "severity": "high",
      "reject_pattern": "R12",
      "title": "Blocklist refusal leaks another profile's fetch and its time",
      "evidence": [
        {"tier": "T4", "claim": "is_blocked(url) is keyed by source only", "source": "database.py:157"},
        {"tier": "T3", "claim": "refusals name nothing", "source": "CLAUDE.md Gateway admin"}
      ],
      "scenario": "Profile A fetches https://x/?slot=7, which is flagged in block mode. Profile B fetches the same URL and is refused with A's detected_at before any network I/O: one bit and a timestamp, persistent.",
      "fix": "Key the blocklist on (profile, source); drop detected_at from the refusal."
    }
  ],
  "proved": ["egress.open_guarded: O6 every hop checked (T3 egress.py, T4 loop pins before send)"]
}
```

Fields:

- `file`, `line`: the line of the defect, not of the function header.
- `obligation`: one code from the Obligations table.
- `verdict`: `UNSOUND` or `UNPROVED`.
- `severity`:
  - `critical`: untrusted content delivered unjudged, or SSRF/local read of
    secrets, reachable by any profile with default config.
  - `high`: a fail-open path, a cross-profile channel, an unaudited denial, or
    an event-loop stall any caller can trigger.
  - `medium`: the same, behind a non-default setting or requiring a second
    condition; or a forgeable trust marker.
  - `low`: UNPROVED only (a missing `# TRUST:`, an unclassified premise), or a
    fail-closed logic bug.
- `evidence`: at least one tier-labelled premise; an UNSOUND finding needs a
  T4 fact at the defect line.
- `scenario`: concrete inputs and calls. Name the profile, the tool, the
  argument, and what the attacker observes or obtains.
- `fix`: the smallest change that discharges the obligation.

With no findings, return `{"findings": [], "proved": [...]}`. That is a valid
and often correct answer.

## Precision discipline

A finding is wrong, and costs the review its credibility, when it flags a
documented contract. Do NOT flag:

- **flag mode proceeding on a truncated head.** `flag` delivers the bytes it
  received with `_trentina_warning` carrying `l2_truncated`/`l3_truncated`.
  That is its documented contract (CLAUDE.md "Layer 2 scanning limits";
  `defense.defend`, `docs/defense-pipeline.md`). It is a finding only if the
  warning is missing, says clean, or the same path serves `block` or `redact`.
- **An `except Exception` that re-raises as a refusal and audits
  `blocked_defense`**, or that only keeps a verdict that already exists (worked
  example 1). The obligation is on what the arm returns, not on its breadth.
- **A log call marked `# logsafe: ours`** with a reason that the text is the
  server's own. `tests/test_log_hygiene.py` enforces the marker; review the
  reason, not the presence of `exc_info`.
- **Logging `redact_source(x)`, `exc_kind(exc)`, `exc_where(exc)`, a profile
  name, or a resolved tool name.** These are the logging rule's allowed forms.
- **Operator-only scope.** State an operator profile (`role: operator`) can
  see across profiles is its job (`gateway/scope.py`, docs/profiles.md Roles).
  Flag it only if an agent-role caller can reach the same result.
- **The circuit breaker keyed by URL** healing for every profile through
  `reconnect_backend`: documented as the point of the tool, with a residual
  rate recorded in #263. Flag new signal it leaks beyond that residual only.
- **`TRENTINA_FETCH_ALLOW_PRIVATE`, `TRENTINA_REQUIRE_L2=false`,
  `TRENTINA_REQUIRE_L3=false`, `TRENTINA_RATE_LIMIT=off`**: default fail-closed,
  documented escape hatches that warn at startup. Flag a change to the default
  or a missing startup warning, not the existence of the switch.
- **Tests, fixtures and benchmarks**, unless the review target is them.
- **Style, naming, complexity or type issues.** Other gates own those.

If you are unsure whether a behavior is a documented contract, find the doc.
If you cannot find one, it is a finding (O13 or UNPROVED), graded `low`.
