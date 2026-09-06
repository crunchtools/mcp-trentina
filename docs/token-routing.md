# Token Routing

Route expensive I/O work to cheap models at the gateway layer. When a coding agent reads a large file or generates boilerplate code, Trentina intercepts the call, delegates it to a smaller model (Gemini Flash, GPT-4o-mini), and returns the result to the frontier model. The frontier model never sees the raw content — it gets a summary or confirmation instead.

## Why This Matters

Most of what a coding agent does isn't reasoning — it's I/O. Reading five files to answer a question about one method. Generating a test file that follows the same pattern as twenty test files next to it. All of it fed to a frontier model (Opus, Fable) that's wildly overqualified for the task. [Spotify reported 90% token savings](https://engineering.atspotify.com/2026/9/portal-by-spotify-cut-my-claude-code-token-usage-by-90) by routing bulk reads to Gemini Flash.

Spotify's implementation is client-side — a Claude Code plugin that intercepts Read calls via hooks and delegates through their Portal backend. The routing rules are advisory: the agent can ignore them. Every project needs its own configuration.

Trentina's implementation is server-side. The gateway already intercepts every tool call for every agent profile. Delegation is enforced — the agent can't bypass it. Configuration lives in `profiles.yaml` alongside the existing tool allowlists, parameter guards, and defense settings. Every agent that connects through the gateway gets routing automatically.

### Cost Context

By 2028, AI coding costs are [projected to exceed average developer salaries](https://www.gartner.com/en/newsroom/press-releases/2026-06-24-gartner-predicts-ai-coding-costs-will-surpass-average-developer-salary-by-2028-as-token-consumption-surges). A quarter of engineering leaders already burn $200–$500/developer/month on tokens. Token routing turns this from a systems engineering problem into a configuration problem — one YAML section per profile.

## How It Works

### Interception Point

Token routing sits in the gateway call pipeline between parameter guards and the backend call:

```
Parse tool → Backend exists? → Tool in allowlist? → Parameter guards → Token routing → Backend call
```

When a tool call matches a routing rule, the gateway short-circuits the normal backend call. Instead:

1. The gateway reads the content itself (file read) or assembles the request (code generation)
2. Sends it to the configured worker model via the LLM proxy
3. Returns the worker's response to the calling agent as if it were the backend's response

The agent never knows delegation happened. From its perspective, it called Read and got a response.

### Two Delegation Modes

#### Mode 1: Bulk Read

For when an agent would read multiple large files just to answer one question.

**Trigger:** A file read tool call where the file exceeds the configured line threshold. Targeted reads (with `offset`/`limit` parameters) pass through — the agent already knows what section it needs.

**Flow:**
```
Agent calls Read(file_path="/src/Service.java")
  → Gateway checks: file is 2,400 lines, threshold is 350
  → Gateway reads the file directly from disk
  → Gateway sends file + agent's surrounding context to worker model
  → Worker returns structured summary (bullets, types, line references)
  → Gateway returns summary to agent (with metadata noting delegation)
```

**Worker prompt:** Tight extraction instructions — "structured bullets only, no prose, no preambles. Lead every bullet with the exact name, type, or line number."

#### Mode 2: Code Generation

For tests, config scaffolding, type stubs, or anything where the output is predictable from existing patterns.

**Trigger:** Explicit delegation via a gateway-provided tool, or pattern detection on Write calls that follow a reference file pattern.

**Flow:**
```
Agent calls delegate_codegen(spec="Write tests for UserService", reference="tests/OrderTest.java", target="tests/UserTest.java")
  → Gateway reads the reference file
  → Gateway sends spec + reference to worker model
  → Worker generates code matching the reference patterns
  → Gateway writes output to target path
  → Gateway returns confirmation to agent (file written, N lines)
```

The frontier model never sees the generated code. The reference file goes to the cheap model, not to the agent's context.

### What Passes Through

Not everything should be delegated. The routing rules explicitly exempt:

- **Targeted reads** — reads with `offset`/`limit` where the agent already knows what section it needs
- **Small files** — below the line threshold, delegation overhead exceeds savings
- **Piped/filtered reads** — `cat file | grep pattern` via Bash is already a targeted read
- **Editing context** — when the agent needs to make edits, it needs the actual content with reliable line numbers (worker summaries don't include these)

## Configuration

### Profile Schema Extension

Token routing is configured per-profile in `profiles.yaml` under a new `delegation` section:

```yaml
profiles:
  coding-worker:
    auth:
      bearer_token_env: TRENTINA_PROFILE_CODING_WORKER_TOKEN
    delegation:
      enabled: true
      worker_model: gemini-2.5-flash
      worker_provider: gemini
      line_threshold: 350
      modes:
        bulk_read:
          enabled: true
          prompt: |
            You are a precise code analyst. Read the provided files and
            answer the question concisely. Output structured bullets only.
            No greetings, no prose, no preambles. Lead every bullet with
            the exact name, type, or line number. Use nested bullets for
            details. Skip anything the caller did not ask for.
        code_write:
          enabled: true
          prompt: |
            You generate code files based on a spec and reference files.
            Match the existing patterns, conventions, naming, and style
            exactly. Output only the code — no explanations, no markdown
            fences unless asked.
    backends:
      # ... normal backend config
    defense:
      # ... normal defense config
```

### Schema Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `delegation.enabled` | bool | `false` | Master switch for token routing |
| `delegation.worker_model` | string | — | Model name for the worker (e.g., `gemini-2.5-flash`, `gpt-4o-mini`) |
| `delegation.worker_provider` | string | — | Provider for the worker model (`gemini`, `openai`, `anthropic`) |
| `delegation.line_threshold` | int | `350` | File line count above which reads are delegated |
| `delegation.temperature` | float | `0.2` | Temperature for worker model calls |
| `delegation.max_input_chars` | int | `100000` | Max chars sent to worker (aligns with `QUARANTINE_MAX_CONTENT`) |
| `delegation.modes.bulk_read.enabled` | bool | `true` | Enable bulk-read delegation |
| `delegation.modes.bulk_read.prompt` | string | (built-in) | System prompt for the bulk-read worker |
| `delegation.modes.code_write.enabled` | bool | `true` | Enable code-write delegation |
| `delegation.modes.code_write.prompt` | string | (built-in) | System prompt for the code-write worker |

### Per-Profile Examples

```yaml
profiles:
  # Human-supervised IDE agent — light delegation
  josui:
    delegation:
      enabled: true
      worker_model: gemini-2.5-flash
      worker_provider: gemini
      line_threshold: 500    # higher threshold — human can redirect

  # Autonomous coding agent — aggressive delegation
  coding-worker:
    delegation:
      enabled: true
      worker_model: gpt-4o-mini
      worker_provider: openai
      line_threshold: 200    # delegate more aggressively
      modes:
        code_write:
          enabled: true

  # Chat agent — no delegation (doesn't read code)
  takeda:
    delegation:
      enabled: false
```

## Implementation

### Gateway Changes

#### New Module: `delegation.py`

Sits alongside `guards.py` in the gateway package. Exports a single function:

```python
async def maybe_delegate(
    profile: Profile,
    tool_name: str,
    arguments: dict,
    llm_proxy: LLMProxy,
) -> dict | None:
    """
    Check if this tool call should be delegated to a worker model.
    Returns the delegated response, or None to proceed normally.
    """
```

Called from `router.py` after parameter guards pass but before the backend call. If it returns `None`, the normal call proceeds. If it returns a dict, that becomes the tool result.

#### File Size Check

For Read-like tools, the delegation module:

1. Resolves the `file_path` argument
2. Counts lines (or uses `os.path.getsize()` as a fast pre-check)
3. If below threshold or if `offset`/`limit` are present, returns `None`
4. If above threshold, reads the file, sends to worker, returns summary

#### Worker Calls via LLM Proxy

Delegation uses the existing LLM proxy infrastructure. The worker call goes through `/llm/{provider}/` with the profile's credentials — no new API key management needed. The worker model is configured per-profile, same as `llm_keys`.

#### Response Metadata

Delegated responses include metadata so the calling agent knows what happened:

```json
{
  "content": "## /src/Service.java (2,417 lines — delegated to gemini-2.5-flash)\n\n- Class `UserService` extends `BaseService`\n  - Line 45: `createUser(...)` — validates input, writes to `users` table\n  ...",
  "delegation": {
    "worker_model": "gemini-2.5-flash",
    "original_lines": 2417,
    "worker_tokens": 1247,
    "saved_tokens_estimate": 18500
  }
}
```

### New Gateway Tool: `delegate_codegen`

Exposed as a gateway-internal tool (like the existing `cache_flush` and `reconnect_backend`):

```
delegate_codegen(spec, reference, target)
```

The tool is only visible to profiles that have `delegation.modes.code_write.enabled: true`. The gateway reads the reference file, sends spec + reference to the worker, writes output to the target path, and returns a confirmation.

### Security Considerations

#### Defense Pipeline Interaction

Delegated content is generated by the worker model from file-system content — it doesn't come from an untrusted external source. The defense pipeline (L1/L2/L3) does **not** run on delegated responses because:

- The input is local files, not web content or user-generated data
- The worker model's output is a summary/extraction, not raw untrusted content
- Running L2/L3 on every delegated response would negate the cost savings

If a profile's delegation source is ever extended to untrusted content (e.g., delegating web fetches), the defense pipeline should run on the worker's output.

#### File System Access

The delegation module needs read access to the file system to count lines and read files for the worker. This is the same access level the backend MCP servers already have — Trentina runs on the same host as the code.

For remote deployments where the agent's file system isn't local to Trentina, the delegation module would need to call through the backend's Read tool first (one cheap backend call to get the content, then delegate to the worker). This adds complexity but preserves the architecture.

#### Worker Model Isolation

The worker model call follows the same isolation principles as the Q-Agent:

- **No tools** — the worker can't execute actions
- **No memory** — each delegation is stateless
- **Tight prompt** — extraction/generation only, no reasoning
- **Low temperature** — 0.2 default, deterministic output

## What Doesn't Work

Taken from Spotify's experience and adapted:

1. **Can't delegate editing** — Worker summaries don't include reliable line numbers. If the agent needs to make edits based on analysis, it still has to read the specific section directly. The line threshold and targeted-read passthrough exist for this reason.

2. **Can't delegate reasoning** — Cheap models miss subtle bugs (thread-safety issues, race conditions, security vulnerabilities). The routing explicitly excludes debugging, architectural decisions, and safety-critical analysis.

3. **Latency adds up** — Each delegation is a network round-trip to the worker model provider. 10-30 seconds per call. Acceptable for large reads (18k tokens saved > 15s wait), counterproductive for small ones (hence the line threshold).

4. **Context fragmentation** — The agent builds understanding from file contents. Summaries lose nuance. For tasks that require deep cross-file understanding, the agent may need to re-read sections that were summarized. The delegation metadata helps the agent decide when to request a targeted re-read.

## Relationship to Existing Features

| Feature | Relationship |
|---------|-------------|
| [LLM Proxy](llm-proxying.md) | Delegation uses the proxy for worker model calls — same key management, same provider support |
| [Parameter Guards](parameter-guards.md) | Guards run before delegation — a rejected call is never delegated |
| [Defense Pipeline](defense-pipeline.md) | Defense runs on backend responses, not delegated responses (see Security) |
| [Per-Agent Profiles](profiles.md) | Delegation is profile-level config — different agents get different routing |
| [Tool Filtering](tool-filtering.md) | `delegate_codegen` tool visibility follows normal allowlist rules |
| [Compression](compression.md) | Complementary — compression shrinks tool descriptions, delegation shrinks tool responses |

## Open Questions

1. **Should delegated summaries be cached?** If the agent re-reads the same large file within a session, should the gateway return the cached summary? Pro: eliminates redundant worker calls. Con: stale summaries if the file changed.

2. **Should the agent be told delegation happened?** Spotify's approach is transparent — the agent doesn't know. But telling the agent enables it to request a targeted re-read when it needs more detail. The metadata sidecar is a middle ground.

3. **Multi-file bundling** — Spotify's bulk-read accepts multiple files in one call. Should Trentina batch adjacent Read calls into a single worker request? This requires call-sequence awareness in the gateway.

4. **Write interception** — Beyond explicit `delegate_codegen`, should the gateway detect when an agent is about to Write boilerplate (e.g., test files that match a pattern) and offer to delegate? This moves into heuristic territory.

5. **Token accounting** — How to report savings. The gateway knows how many tokens the worker consumed and can estimate how many the frontier model would have consumed. This data belongs in the audit log.
