"""Pydantic v2 models for gateway profile configuration.

Profiles are loaded from YAML and define which backend MCP servers a consumer
can reach, which tools per backend are allowed, and which defense layers
apply to responses. Phase 1 stores the defense flags but does not apply
them — Phase 2 wires the defense pipeline in.

All models use `extra="forbid"` per the constitution; unrecognized keys in
profile YAML are a hard error at load time.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)

from ..config import SUPPORTED_PROVIDERS

logger = logging.getLogger(__name__)

PROFILE_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
BACKEND_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
PROVIDER_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
GLOB_PATTERN_RE = re.compile(r"^[a-zA-Z0-9_*][a-zA-Z0-9_*-]*$")
GUARD_VALUE_RE = re.compile(r"^[a-zA-Z0-9_*@.\-+/ ]+$")
ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")

GOOGLE_ISSUER = "https://accounts.google.com"
"""Google's OIDC issuer, verbatim as Google publishes it.

No trailing slash — confirmed against Google's own discovery document. A client
compares the issuer it discovered against the one we advertise byte-for-byte
(RFC 8414 3.3), so this string is never normalized.
"""

SUPPORTED_ISSUERS = frozenset({GOOGLE_ISSUER})
"""Issuers this build can actually verify tokens from.

The issuer selects a verifier, so the set is a hard allowlist rather than a
hint: accepting one we have no verifier for would fail at request time instead
of at load. Keycloak is the intended next entry.
"""

INTERNAL_SCHEME = "internal://"

# What a profile may reach through the gateway's own admin tools. Two values,
# because the only distinction that matters is "my slice" versus "the whole
# gateway" — an agent profile sees and acts on itself, the operator seat holds
# the box. See gateway/scope.py, which is the only place this is interpreted.
ProfileRole = Literal["agent", "operator"]

#: The three things a flagged payload can become, named for what the reading
#: agent is told rather than for the mechanism that tells it. `warn` forwards
#: the original bytes with the caution attached, `block` refuses. Spelled
#: `annotate`/`block` before 0.25.0. `clean` is deliberately absent — see
#: `_normalize_enforcement`.
EnforcementMode = Literal["warn", "block"]

def _normalize_enforcement(block: Any, *, key: str) -> Any:
    """Migrate the old spellings, and refuse `clean` with an explanation.

    **Why there is no `clean` enforcement mode.** As a TOOL it exists and
    works: `clean_fetch` hands the page to the Q-Agent and returns what comes
    back. As an enforcement mode it never has. The gateway shipped `extract`
    on 2026-09-13 deliberately unimplemented, with a log line saying so,
    because the config surface was built ahead of the flip.

    The two are not the same code and cannot trivially be. Extraction needs a
    PROMPT. On the tool path the agent supplies one. At the gateway the agent
    called `jira_get_issue`, not "extract something from this", so there is no
    instruction to extract against — and inventing one means deciding what
    extraction means for an arbitrary backend's structured response.

    0.26.0 renamed both sides to the word `clean` and so made a known gap read
    like a promise. A config must not name a capability the gateway does not
    have, so this refuses it at load.

    Pydantic would refuse it anyway now that it is out of the Literal, but it
    would say "input should be 'warn' or 'block'" — which tells an operator
    the word is wrong, not that the FEATURE is missing, and sends them hunting
    for a typo in a value they read in our own documentation. A profile that
    fails to load is fatal, so the one line they get has to be the line that
    explains it.
    """
    if not isinstance(block, dict):
        return block
    old = block.get("enforcement")
    if old == "clean":
        raise ValueError(
            f"{key}: enforcement 'clean' is not implemented and never has "
            f"been — the gateway has no extraction instruction to work from "
            f"on a proxied response. Use 'warn' (deliver the content with "
            f"the verdict attached) or 'block' (refuse it). The clean_* "
            f"TOOLS are unaffected and continue to work."
        )
    return block

# Pre-0.21.0 l2_input.extractor names. 'full' is not here: it maps to an
# empty processor list rather than to a name.
_EXTRACTOR_RENAMES: dict[str, str] = {"generic": "select"}

# Registered pre-processors. Adding one means adding it here, to
# gateway.drivers.PREPROCESSORS, and nowhere else. Declared twice on purpose:
# this Literal is what makes pydantic reject an unknown name at YAML load,
# and the parity test in tests/test_gateway_drivers.py keeps the two in step.
ProcessorName = Literal[
    # TEXT — str in, str out. Valid on the tool channel.
    "petit",
    "structured",
    "email",
    "html",
    "summarize",
    # DOCUMENT — parsed JSON in, the strings worth reading out. Valid on the
    # matrix channel. `select` alone reads any JSON; `matrix` decrypts first.
    # There is no "full": reading everything is what naming nothing means.
    "select",
    "matrix",
]
# FREE only. `html` runs FIRST: it is the only CONVERTER, so the reducers
# behind it group the text a human would read rather than tag soup, and its
# absence costs a whole attack class (`l1/hidden.py`, tier 1).
#
# The rest are ordered by how cheaply each can decline; petit has to group
# every line before it knows, so it goes last. summarize is selectable but
# never a default: METERED, and its output draws unconditional L3.
_DEFAULT_PROCESSORS: list[ProcessorName] = ["html", "structured", "email", "petit"]

# Fields of MatrixPreProcessConfig an AGENT may change by reloading its own
# profile.
# Everything else in that block decides how much of the payload is read at
# all -- an agent may retune its own performance, it may not reshape its own
# perimeter. Enforced in tools/reload.py.
PREPROCESS_AGENT_FIELDS: frozenset[str] = frozenset(
    {"skip_sample_bytes", "min_coverage", "deadline_seconds"}
)

# 64 KiB of sampled openings is already ~36 L2 windows, which costs more than
# the extraction saved. A ceiling, not a recommendation.
_MAX_SKIP_SAMPLE_BYTES = 65536

# A Megolm session per room-key; a bot in a hundred rooms holds a few hundred.
# 4096 is generous headroom, and the ceiling keeps a typo from asking for an
# unbounded in-memory store of decryption capabilities.
_DEFAULT_MAX_SESSIONS = 4096
_MAX_MAX_SESSIONS = 65536

# Reduction budget, in bytes of a single tool response.
#
# ~20 KB is roughly 5K tokens: large enough that ordinary responses pass
# through untouched, small enough that the handful of replies which
# dominate a transcript get attention. Only the `auto` strategy binds on
# it, as the ceiling above which METERED processors are allowed.
DEFAULT_TARGET_BYTES = 20_000

# Floor below which a response is passed through untouched. Reduction has
# a fixed cost — a parse, a walk, and for METERED a model call — and a
# payload this small cannot repay it however well it compresses.
DEFAULT_MIN_BYTES = 4_096

MAX_BACKEND_TIMEOUT_SECONDS = 300.0
MAX_LIST_TIMEOUT_SECONDS = 60.0


class AuthConfig(BaseModel):
    """Per-profile bearer-token auth config.

    `bearer_token_env` is the env var name holding the actual token value;
    `bearer_token` is resolved at load time and never serialized.
    """

    model_config = ConfigDict(extra="forbid")

    bearer_token_env: str = Field(
        ..., description="Env var name whose value is the profile's bearer token"
    )
    bearer_token: SecretStr | None = Field(
        default=None, exclude=True, description="Resolved token (load-time only)"
    )

    @field_validator("bearer_token_env")
    @classmethod
    def env_name_is_uppercase_identifier(cls, v: str) -> str:
        """Reject lowercase, leading digits, or non-identifier characters."""
        if not ENV_NAME_RE.match(v):
            raise ValueError(
                f"bearer_token_env {v!r} must be an UPPERCASE env-var identifier"
            )
        return v


class LlmKeyOverride(BaseModel):
    """Per-profile provider API key for the LLM reverse proxy.

    Provide EITHER `api_key` (direct value, for bind-mounted configs) OR
    `api_key_env` (env var reference). The `api_key` field holds the resolved
    key at load time and is never serialized to logs/JSON.
    """

    model_config = ConfigDict(extra="forbid")

    api_key_env: str | None = Field(
        default=None,
        description="Env var name whose value is this profile's provider API key",
    )
    api_key: SecretStr = Field(
        default=SecretStr(""),
        description=(
            "Direct API key value (for bind-mounted configs) or resolved from "
            "api_key_env at load time. Never serialized."
        ),
    )

    @field_validator("api_key_env")
    @classmethod
    def env_name_is_uppercase_identifier(cls, v: str | None) -> str | None:
        """Reject lowercase, leading digits, or non-identifier characters."""
        if v is not None and not ENV_NAME_RE.match(v):
            raise ValueError(
                f"api_key_env {v!r} must be an UPPERCASE env-var identifier"
            )
        return v

    @field_validator("api_key", mode="before")
    @classmethod
    def coerce_to_secret_str(cls, v: str | SecretStr) -> SecretStr:
        """Accept plain strings from YAML and wrap in SecretStr."""
        if isinstance(v, str):
            return SecretStr(v)
        return v


class ParameterConstraint(BaseModel):
    """Allow/deny constraint on a single tool parameter's value."""

    model_config = ConfigDict(extra="forbid")

    allow: list[str] = Field(
        default_factory=lambda: ["*"],
        description="Value glob patterns to allow (default: all)",
    )
    deny: list[str] = Field(
        default_factory=list,
        description="Value glob patterns to deny (wins over allow)",
    )

    @field_validator("allow", "deny")
    @classmethod
    def guard_values_valid(cls, v: list[str]) -> list[str]:
        for pat in v:
            if not GUARD_VALUE_RE.match(pat):
                raise ValueError(
                    f"Invalid guard value {pat!r}: allowed characters are "
                    "alphanumerics, underscore, hyphen, dot, at-sign, plus, "
                    "forward-slash, space, and '*'"
                )
        return v


class ProcessorChainConfig(BaseModel):
    """What every channel's pre-processing has in common: which, and how much.

    Two channels configure pre-processing and they want different knobs
    around the same chain — the tool channel has a size budget, the matrix
    channel has a coverage floor and a deadline. Rather than one model whose
    fields are half-meaningless wherever you look, both inherit this.

    ``gateway/drivers.py`` types against this base, so it is exactly the
    surface the registry needs and nothing else.
    """

    model_config = ConfigDict(extra="forbid")

    processors: list[ProcessorName] = Field(
        default_factory=list,
        description="Which processors run, in order. Empty is the no-op.",
    )
    skip_sample_bytes: int = Field(
        default=1024,
        ge=0,
        le=_MAX_SKIP_SAMPLE_BYTES,
        description=(
            "Budget for sampling the opening of skipped strings, so a payload "
            "hidden in a declined field still reaches L1/L2. Zero disables "
            "the backstop -- do that only with a reason. Read by 'select' "
            "and 'matrix'; ignored by the text processors."
        ),
    )


class PreProcessConfig(ProcessorChainConfig):
    """Transformation applied to tool responses before the perimeter scan.

    Transformation is not defense (see ``preprocess/base.py``, invariant 1: a
    pre-processor may subtract, never absolve). What this configures is how
    hard to try to improve a payload; what comes out is exactly as untrusted
    as what went in, and the caller scans the transformed artifact before
    delivering it.

    Every processor available today reduces, and both selection strategies
    below judge on size — so this reads as a reduction budget in practice.

    Resolution is two-level and least-surprise: a tool's entry in the
    backend's ``preprocess_tools`` wins over the profile default, and any
    field it leaves unset inherits. Profile answers "how aggressive is this
    agent"; tool answers "is this payload shape worth it".
    """

    enabled: bool = Field(
        default=False,
        description="Master switch. Off means the response is untouched.",
    )
    strategy: Literal["none", "chain", "best_of", "auto"] = Field(
        default="auto",
        description=(
            "How processors compose. auto runs FREE ones always and "
            "escalates to METERED only while the payload exceeds "
            "target_bytes; chain feeds each the previous output; best_of "
            "keeps whichever came out smallest."
        ),
    )
    processors: list[ProcessorName] = Field(
        default_factory=lambda: list(_DEFAULT_PROCESSORS),
        description=(
            "Which processors may run, in order. 'summarize' is METERED: it "
            "spends an LLM call AND forces its output to MODEL_OUTPUT "
            "provenance, which draws unconditional L3 — two model calls per "
            "response, not one. Default is the FREE set. 'select' and "
            "'matrix' are document processors and are refused here."
        ),
    )
    target_bytes: int = Field(
        default=DEFAULT_TARGET_BYTES,
        ge=0,
        description=(
            "Size the reducer is trying to get under. Only 'auto' binds on "
            "it, as the ceiling above which METERED processors are allowed."
        ),
    )
    min_bytes: int = Field(
        default=DEFAULT_MIN_BYTES,
        ge=0,
        description=(
            "Floor below which the response is passed through untouched. "
            "Reduction has a fixed cost and small payloads cannot repay it."
        ),
    )


class ToolPreProcess(BaseModel):
    """Per-tool override. Every field is optional; unset inherits the profile."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    strategy: Literal["none", "chain", "best_of", "auto"] | None = None
    processors: list[ProcessorName] | None = None
    target_bytes: int | None = Field(default=None, ge=0)
    min_bytes: int | None = Field(default=None, ge=0)


class Backend(BaseModel):
    """Per-profile backend MCP server config."""

    model_config = ConfigDict(extra="forbid")

    url: str = Field(
        ...,
        description=(
            "Backend location. Either a streamable-http URL (http(s)://) or "
            "internal://<label> for trentina's own in-process tool surface."
        ),
    )
    tools_allow: list[str] = Field(
        default_factory=lambda: ["*"],
        description="Tool-name glob patterns to allow (default: all)",
    )
    tools_deny: list[str] = Field(
        default_factory=list,
        description="Tool-name glob patterns to deny (wins over tools_allow)",
    )
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="Extra HTTP headers to send to the backend",
    )
    timeout_seconds: float = Field(
        default=30.0,
        gt=0,
        le=MAX_BACKEND_TIMEOUT_SECONDS,
        description="Per-call backend timeout",
    )
    list_timeout_seconds: float = Field(
        default=30.0,
        gt=0,
        le=MAX_LIST_TIMEOUT_SECONDS,
        description=(
            "Timeout for tools/list metadata fetch "
            "(streamable-HTTP handshake needs headroom)"
        ),
    )
    parameter_guards: dict[str, dict[str, ParameterConstraint]] = Field(
        default_factory=dict,
        description=(
            "Tool name -> parameter name -> value constraint. "
            "Validated at call time before the backend is contacted."
        ),
    )
    response_guards: dict[str, dict[str, ParameterConstraint]] = Field(
        default_factory=dict,
        description=(
            "Tool name -> response field -> value constraint. Validated on "
            "the backend's result before it is reduced, scanned or relayed. "
            "A field is a key of structuredContent, or the reserved name "
            "'content' for the result's concatenated text. A violation "
            "rejects the whole response — nothing partial is delivered."
        ),
    )
    validate_output_schema: bool = Field(
        default=True,
        description=(
            "Validate tool results against the backend's outputSchema "
            "(disable for buggy backends)"
        ),
    )
    compress_descriptions: bool = Field(
        default=False,
        description="Compress verbose tool descriptions via LLM at gateway startup",
    )
    preprocess_tools: dict[str, ToolPreProcess] = Field(
        default_factory=dict,
        description=(
            "Per-tool response-reduction overrides, keyed by tool name "
            "(same shape as parameter_guards). Whether reduction helps is a "
            "property of the tool's OUTPUT SHAPE, not of who called it: "
            "syslog_tail_tool is log-shaped for every profile. Unset tools "
            "use the profile default."
        ),
    )

    @field_validator("url")
    @classmethod
    def url_scheme_supported(cls, v: str) -> str:
        """Allow http(s):// (remote MCP) or internal://<label> (trentina's own tools).

        SSE and stdio are not supported. An internal:// URL must carry a
        URL-safe slug label after the scheme (cosmetic, but required so the
        namespace stays well-formed).
        """
        if v.startswith(("http://", "https://")):
            return v
        if v.startswith(INTERNAL_SCHEME):
            label = v[len(INTERNAL_SCHEME) :]
            if not BACKEND_NAME_RE.match(label):
                raise ValueError(
                    f"internal:// URL must carry a slug label "
                    f"(^[a-z][a-z0-9-]*$): {v!r}"
                )
            return v
        raise ValueError(
            f"Backend URL must start with http://, https://, or internal://: {v!r}"
        )

    @property
    def is_internal(self) -> bool:
        """True when this backend resolves to trentina's in-process tool surface."""
        return self.url.startswith(INTERNAL_SCHEME)

    @field_validator("tools_allow", "tools_deny")
    @classmethod
    def glob_patterns_valid(cls, v: list[str]) -> list[str]:
        """Each glob must match GLOB_PATTERN_RE — restricted character set, no regex metachars."""
        for pat in v:
            if not GLOB_PATTERN_RE.match(pat):
                raise ValueError(
                    f"Invalid glob pattern {pat!r}: allowed characters are "
                    "alphanumerics, underscore, hyphen, and '*'; first character "
                    "may not be a hyphen"
                )
        return v


class AlertIngressConfig(BaseModel):
    """Per-profile alert webhook ingress.

    Receives external alert POSTs (e.g. from Nagios) at ``/alert/{token}``
    and forwards the JSON payload to ``forward_url`` (e.g. a Hermes webhook).
    The token embedded in the URL is the sole authentication mechanism.
    """

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def _check_enforcement(cls, block: Any) -> Any:
        return _normalize_enforcement(block, key="alert_ingress")

    token_env: str = Field(
        ..., description="Env var name whose value is the alert ingress token",
    )
    token: SecretStr | None = Field(
        default=None, exclude=True, description="Resolved token (load-time only)",
    )
    enforcement: EnforcementMode = Field(
        default="warn",
        description=(
            "What a flagged alert payload becomes. There is no agent to ask on a "
            "PUSH path — nobody is waiting to pick a mode per call — so it "
            "is set here. Defaults to warn, which is what this path already "
            "did before the setting existed: forward the payload with the "
            "caution attached. For paging that is the right default, because "
            "silently dropping a real incident on a classifier false "
            "positive is worse than forwarding a flagged one, and the "
            "warning lands in context ahead of the payload so the receiving "
            "agent reads it first. Advisory, not a substitute for L1/L2/L3 "
            "catching the thing: a convincing enough injection can still "
            "talk an agent past its own warning."
        ),
    )
    forward_url: str = Field(
        ..., description="URL to forward alert payloads to",
    )
    forward_secret_env: str | None = Field(
        default=None,
        description="Env var for HMAC secret used to sign forwarded payloads",
    )
    forward_secret: SecretStr | None = Field(
        default=None, exclude=True, description="Resolved HMAC secret (load-time only)",
    )

    @field_validator("forward_secret_env")
    @classmethod
    def forward_secret_env_is_uppercase(cls, v: str | None) -> str | None:
        if v is not None and not ENV_NAME_RE.match(v):
            raise ValueError(
                f"forward_secret_env {v!r} must be an UPPERCASE env-var identifier"
            )
        return v

    @field_validator("token_env")
    @classmethod
    def env_name_is_uppercase_identifier(cls, v: str) -> str:
        if not ENV_NAME_RE.match(v):
            raise ValueError(
                f"token_env {v!r} must be an UPPERCASE env-var identifier"
            )
        return v

    @field_validator("forward_url")
    @classmethod
    def url_must_be_http(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError(
                f"forward_url must start with http:// or https://: {v!r}"
            )
        return v


class DefenseConfig(BaseModel):
    """Per-profile defense policy, read by the shared pipeline.

    There are deliberately NO on/off switches for the layers (owner's call,
    2026-09-13): the earlier schema had `sanitize`/`classify`/`quarantine`
    booleans, and production ran `quarantine: false` for months without the
    owner knowing — partly because none of it was wired, partly because
    three unrelated words hid what they controlled. A profile behind
    Trentina gets all three layers, full stop; what a profile controls is
    THRESHOLDS (how suspicious before a layer flags or escalates) and the
    ENFORCEMENT consequence. A layer that is genuinely unavailable at
    runtime (no ONNX model, provider down) is a degraded state that /health
    reports and block-mode refuses on — never a config option that fails
    silent.

    There is no cost control for L3 any more, and that is the point. It used
    to live in an `l3_threshold` key, which meant clean traffic never reached the
    judge — and since L2 FLAGS at `l2_threshold` while escalation needed
    that gate, there was a band L2 flagged that L3 never reviewed.

    That was read as satisfying "all three layers, full stop" because it
    removed the per-layer booleans. It did not: a threshold deciding whether
    a layer executes is an off switch with a dial on it. The mandate is that
    L1, L2 and L3 run on every input to the gateway. They do, and
    the key no longer exists and a profile setting it fails to load.

    What a profile still controls is `l2_threshold` — how suspicious L2 must
    be before it FLAGS, which is a consequence and not an execution — and
    `enforcement`, which is what a flag costs.
    """

    model_config = ConfigDict(extra="forbid")

    enforcement: EnforcementMode = Field(
        default="warn",
        description=(
            "What a flagged tool response becomes. warn: delivered intact "
            "with a _trentina_warning attached, so the reading agent sees "
            "the caution before the content. block: refused outright. "
            "There is no `clean` here — the clean_* TOOLS exist, the "
            "enforcement mode never has. "
            "TRENTINA_ENFORCEMENT_OVERRIDE=warn is the kill switch: it "
            "forces warn everywhere for the night block misfires."
        ),
    )

    @model_validator(mode="before")
    @classmethod
    def _check_enforcement(cls, block: Any) -> Any:
        return _normalize_enforcement(block, key="defense")

    l2_threshold: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description=(
            "L2 (Prompt Guard) score at or above which the content is "
            "flagged, in addition to the model's own MALICIOUS label"
        ),
    )
    audit: bool = Field(default=True, description="Write detection rows to SQLite")
    provider: str | None = Field(
        default=None,
        description=(
            "LLM provider override for this profile "
            "(falls back to TRENTINA_MODEL_PROVIDER)"
        ),
    )
    model: str | None = Field(
        default=None,
        description=(
            "LLM model override for this profile "
            "(falls back to QUARANTINE_MODEL)"
        ),
    )

    @field_validator("provider")
    @classmethod
    def provider_is_supported(cls, v: str | None) -> str | None:
        """If set, must be a known provider name."""
        if v is not None and v not in SUPPORTED_PROVIDERS:
            raise ValueError(
                f"Unknown provider {v!r}. Supported: {', '.join(SUPPORTED_PROVIDERS)}"
            )
        return v


class MatrixDecryptConfig(BaseModel):
    """Read room keys from the homeserver's backup, to scan message bodies.

    Off by default, and deliberately verbose to turn on. Enabling it means
    Trentina holds a recovery key — the private half of the room-key backup,
    and the most valuable secret in the deployment — so the config should read
    like a decision rather than a default.

    What it does NOT do is worth stating: Trentina takes no Matrix device
    identity, uploads nothing, and makes only GET requests. Decryption exists
    to build the L2 input. The response forwarded to the client is the
    upstream ciphertext, untouched.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = Field(
        default=False,
        description="Read room keys from backup so message bodies can be scanned",
    )
    homeserver: str = Field(
        default="https://matrix.org",
        description="Homeserver base URL to read the key backup from (https only)",
    )
    access_token_env: str = Field(
        ...,
        description="Env var naming the access token used to read the backup",
    )
    recovery_key_env: str = Field(
        ...,
        description=(
            "Env var naming the backup recovery key. Prefer the _FILE form so "
            "it lands in a mode-0600 file rather than /proc/<pid>/environ."
        ),
    )
    access_token: SecretStr | None = Field(default=None, exclude=True)
    recovery_key: SecretStr | None = Field(default=None, exclude=True)

    max_sessions: int = Field(
        default=_DEFAULT_MAX_SESSIONS,
        ge=1,
        le=_MAX_MAX_SESSIONS,
        description=(
            "Megolm sessions held in memory. Each is a decryption capability "
            "for its slice of history, so the cache is bounded rather than "
            "unlimited, and nothing is written to disk."
        ),
    )
    session_ttl_seconds: float = Field(default=3600.0, gt=0)
    concurrency: int = Field(default=4, ge=1, le=32)
    refetch_cooldown_seconds: float = Field(
        default=60.0,
        ge=0.0,
        description=(
            "Minimum gap between key fetches for one room. A rate limit, not "
            "a cache tuning: session IDs arrive in events, so without it any "
            "room member could turn every /sync into N homeserver round-trips "
            "inside the request path."
        ),
    )
    undecryptable_rate_warn: float = Field(default=0.10, ge=0.0, le=1.0)

    @field_validator("homeserver")
    @classmethod
    def _https_only(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("homeserver must be https://")
        return value.rstrip("/")

    @field_validator("access_token_env", "recovery_key_env")
    @classmethod
    def _env_name(cls, value: str) -> str:
        if not ENV_NAME_RE.match(value):
            raise ValueError(f"{value!r} is not an env var name")
        return value


class MatrixPreProcessConfig(ProcessorChainConfig):
    """Pre-processing on the matrix channel, and how coverage gaps are reported.

    The default is an empty chain -- read every string leaf, which is what
    shipped before any selection existed. That default is load-bearing:
    merging this changes no deployment's behaviour until an operator opts in,
    and a defense change whose default narrows the perimeter is one that lands
    by accident.

    This was the ``scan_view:`` block with an ``extractor:`` field naming one
    of full/generic/matrix. ``extractor: full`` became an empty ``processors``
    list, because reading everything is what naming nothing means, and
    ``generic`` became ``select``. Those spellings loaded with a warning from
    0.21.0 and are gone as of 0.29.0: a config still carrying one now fails
    to load rather than resolving to something the operator did not write.
    """

    model_config = ConfigDict(extra="forbid")

    min_coverage: float = Field(
        default=0.02,
        ge=0.0,
        le=1.0,
        description=(
            "Below this fraction of characters read, the response carries a "
            "low_scan_coverage warning. Not a block: an observable, on the "
            "same channel as l2_truncated."
        ),
    )
    deadline_seconds: float = Field(
        default=20.0,
        gt=0.0,
        le=120.0,
        description=(
            "How long pre-processing plus judgement may take before the "
            "response forwards anyway, annotated scan_timeout."
        ),
    )
    decrypt: MatrixDecryptConfig | None = Field(
        default=None,
        description="Matrix E2EE termination. Requires the 'matrix' processor.",
    )

    @model_validator(mode="after")
    def _decrypt_needs_the_matrix_processor(self) -> MatrixPreProcessConfig:
        if self.decrypt is not None and "matrix" not in self.processors:
            raise ValueError(
                "l2_input.decrypt requires processors: [matrix] — the "
                "'select' processor has nowhere to put decrypted text"
            )
        return self


class MatrixIngressConfig(BaseModel):
    """Per-profile access to the Matrix reverse proxy.

    The proxy at ``/matrix/{token}/{path}`` forwards to the homeserver only
    for a token that resolves to a profile. Before this existed the proxy
    was an open relay: anything that could reach the port could use
    Trentina as a Matrix client proxy, unauthenticated and unattributed.
    Token-in-path mirrors the alert ingress and costs the Matrix client
    nothing — the homeserver URL configured in the agent simply includes
    the token as a path prefix.
    """

    model_config = ConfigDict(extra="forbid")

    token_env: str = Field(
        ..., description="Env var name whose value is the Matrix proxy token",
    )
    token: SecretStr | None = Field(
        default=None, exclude=True, description="Resolved token (load-time only)",
    )
    # Deliberately NO `enforcement` here, unlike alert_ingress. This path
    # forwards a STREAMED /sync response, and refusing one does not drop a
    # message — it breaks the client's sync loop, which is the proxy eating
    # the agent's Matrix traffic rather than filtering it. A flagged event
    # forwards annotated, always. Recorded as a deliberate non-change in
    # spec 013 and re-affirmed in 0.25.0 when the alert path became
    # configurable. If this ever needs a mode, the mode is per-EVENT and
    # drops the event from the timeline, not per-response.
    preprocess: MatrixPreProcessConfig = Field(
        default_factory=MatrixPreProcessConfig,
        description=(
            "How much of a Matrix response the defense pipeline reads. "
            "Defaults to scanning everything, so adopting this is an "
            "explicit operator decision rather than a silent narrowing."
        ),
    )


class OAuthConfig(BaseModel):
    """Per-profile Google-backed OAuth access, opt-in on top of static bearer.

    A profile always carries a static bearer (``auth``). When ``oauth.enabled``
    is set it ALSO accepts a Google-backed OAuth token whose verified email is
    in ``allowed_emails`` — the seat for a client that cannot send a static
    ``Authorization`` header (gemini.google.com Custom Apps, which offers only
    "no auth" or OAuth). The static token keeps working for every other client.

    There is no secret in this block: the UPSTREAM Google client credentials are
    a gateway-wide setting (``TRENTINA_OAUTH_GOOGLE_CLIENT_ID`` /
    ``_CLIENT_SECRET``), not per-profile, and the DOWNSTREAM client secret is
    named here by env var rather than written here. What a profile holds is the
    authorization decision — who may use it — which is not a secret and belongs
    in the config the operator reads.

    ``client_id``/``client_secret_env``/``client_redirect_uris`` declare a
    statically provisioned CONFIDENTIAL client of OUR authorization server: one
    whose credentials the operator types into a third-party console rather than
    one that registers itself through DCR. See CHANGELOG 0.9.0.

    ``issuer``/``audience_env`` select the other mode entirely: DELEGATED. The
    profile stops using Trentina as an authorization server and names an
    external one, so the client authenticates straight to that IdP and hands us
    the token it minted. We verify it and apply ``allowed_emails`` — the only
    authorization decision this block ever really made.

    gemini.google.com Custom Apps is why delegated mode exists. Its connector
    offers an MCP server URL, a Client ID and a Client Secret and NO
    authorization or token URL, so it reads our RFC 9728 document, finds
    Trentina named as the authorization server, and refuses to token-exchange
    against an AS it has no relationship with: ``/authorize``, ``/consent`` and
    ``/auth/callback`` all complete and ``POST /token`` is never issued at all.
    Naming Google in that document instead is what unblocks it.

    The two modes are mutually exclusive — see
    ``delegated_excludes_provisioned_client``. In delegated mode ``audience`` is
    the security boundary, not a formality: a Google token verifies for ANY
    OAuth client unless its ``aud`` is pinned, so without it every third-party
    app an allowlisted human ever authorized would hold a credential for this
    profile. See ``docs/authentication.md`` and RT #1502.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = Field(
        default=False,
        description="Accept Google-backed OAuth tokens for this profile",
    )
    allowed_emails: list[str] = Field(
        default_factory=list,
        description=(
            "Verified Google account emails permitted through this profile. "
            "Compared case-insensitively. Empty while enabled is a hard error "
            "— an OAuth seat open to any Google account is never intended."
        ),
    )
    client_id: str | None = Field(
        default=None,
        description=(
            "Client ID of a statically provisioned confidential OAuth client, "
            "as typed into the third-party console. Requires "
            "client_secret_env and client_redirect_uris."
        ),
    )
    client_secret_env: str | None = Field(
        default=None,
        description=(
            "Env var name whose value is that client's secret. The secret "
            "itself is never written in this file."
        ),
    )
    client_secret: SecretStr | None = Field(
        default=None,
        exclude=True,
        description="Resolved client secret (load-time only)",
    )
    allowed_redirect_uris: list[str] = Field(
        default_factory=list,
        description=(
            "Extra callback URLs a self-registering (DCR) client may use for "
            "this profile, on top of the gateway defaults. Exact https URLs "
            "only -- see the validator for why wildcards are refused."
        ),
    )
    client_redirect_uris: list[str] = Field(
        default_factory=list,
        description=(
            "Exact redirect URIs the provisioned client may use. Matched "
            "verbatim — a provisioned client gets no pattern matching."
        ),
    )
    issuer: str | None = Field(
        default=None,
        description=(
            "External OIDC issuer to delegate authentication to, stored "
            "verbatim. Requires audience_env. Absent means proxy mode."
        ),
    )
    audience_env: str | None = Field(
        default=None,
        description=(
            "Env var name whose value is the OAuth client ID tokens must be "
            "issued to. This is the delegated-mode security boundary."
        ),
    )
    audience: str | None = Field(
        default=None,
        exclude=True,
        description="Resolved expected `aud` (load-time only)",
    )

    @field_validator("client_secret_env")
    @classmethod
    def client_secret_env_is_uppercase_identifier(cls, v: str | None) -> str | None:
        """Reject lowercase, leading digits, or non-identifier characters."""
        if v is not None and not ENV_NAME_RE.match(v):
            raise ValueError(
                f"client_secret_env {v!r} must be an UPPERCASE env-var identifier"
            )
        return v

    @field_validator("audience_env")
    @classmethod
    def audience_env_is_uppercase_identifier(cls, v: str | None) -> str | None:
        """Reject lowercase, leading digits, or non-identifier characters."""
        if v is not None and not ENV_NAME_RE.match(v):
            raise ValueError(
                f"audience_env {v!r} must be an UPPERCASE env-var identifier"
            )
        return v

    @field_validator("issuer")
    @classmethod
    def issuer_is_a_bare_https_origin(cls, v: str | None) -> str | None:
        """Validate the issuer without normalizing it.

        The string is stored exactly as written because a client compares the
        issuer it discovered against this one byte-for-byte (RFC 8414 3.3), and
        Google publishes ``https://accounts.google.com`` with NO trailing
        slash. Appending one "helpfully" is how 0.8.1 broke, in mirror image.

        Only issuers we have a verifier for are accepted. The issuer selects a
        verifier; there is no generic fallback, so an unknown one must fail at
        load rather than resolve to nothing at request time.
        """
        if v is None:
            return None
        issuer = v.strip()
        if not issuer.startswith("https://"):
            raise ValueError(f"issuer {issuer!r} must be an https:// URL")
        if "?" in issuer or "#" in issuer:
            raise ValueError(f"issuer {issuer!r} must carry no query or fragment")
        if issuer not in SUPPORTED_ISSUERS:
            supported = ", ".join(sorted(SUPPORTED_ISSUERS))
            raise ValueError(
                f"issuer {issuer!r} has no verifier in this build — "
                f"supported: {supported}"
            )
        return issuer

    @model_validator(mode="after")
    def delegated_client_is_all_or_nothing(self) -> OAuthConfig:
        """A delegated profile needs an issuer, an audience and oauth enabled.

        ``audience_env`` is required rather than optional because it IS the
        security boundary: a Google access token verifies for any OAuth client
        unless its ``aud`` is pinned, so an unpinned delegated profile accepts
        a token minted for any app the allowlisted human ever authorized. The
        allowlist does not save us — those tokens carry the same email.
        """
        if self.issuer is not None and self.audience_env is None:
            raise ValueError(
                "oauth.issuer requires oauth.audience_env — an unpinned "
                "audience accepts tokens minted for any other OAuth client"
            )
        if self.audience_env is not None and self.issuer is None:
            raise ValueError(
                "oauth.audience_env is set without oauth.issuer, so it would "
                "never be consulted"
            )
        if self.issuer is not None and not self.enabled:
            raise ValueError(
                "a delegated OAuth profile requires oauth.enabled — a profile "
                "naming an external issuer while OAuth is off is a "
                "misconfiguration, not a degraded mode"
            )
        return self

    @model_validator(mode="after")
    def delegated_excludes_provisioned_client(self) -> OAuthConfig:
        """Refuse a profile that is both delegated and a provisioned client.

        The provisioned fields register a client against OUR authorization
        server; in delegated mode we run none for this profile. Left combined
        this is a widening rather than dead config: the gateway registers every
        provisioned ``client_id`` into the one shared proxy, where it becomes a
        live confidential client for the OTHER profiles' authorization server.
        """
        if self.issuer is not None and self.client_id is not None:
            raise ValueError(
                "oauth.issuer (delegated) and oauth.client_id (provisioned "
                "client of our own authorization server) are mutually "
                "exclusive — a delegated profile runs no authorization server"
            )
        return self

    @model_validator(mode="after")
    def provisioned_client_is_all_or_nothing(self) -> OAuthConfig:
        """A half-declared confidential client must not start.

        Each piece is useless alone and a missing piece fails in a way that is
        hard to read from the outside: no client_id and the secret is never
        consulted; no redirect URI and every /authorize is rejected as an
        unregistered redirect. Refuse at load instead.
        """
        declared = {
            "client_id": self.client_id is not None,
            "client_secret_env": self.client_secret_env is not None,
            "client_redirect_uris": bool(self.client_redirect_uris),
        }
        if any(declared.values()) and not all(declared.values()):
            missing = sorted(k for k, present in declared.items() if not present)
            raise ValueError(
                "a provisioned OAuth client needs client_id, client_secret_env "
                f"and client_redirect_uris together — missing {', '.join(missing)}"
            )
        if self.client_id is not None and not self.enabled:
            raise ValueError(
                "a provisioned OAuth client requires oauth.enabled — a client "
                "that can authenticate but reaches a profile with OAuth off is "
                "a misconfiguration, not a degraded mode"
            )
        return self

    @field_validator("allowed_emails")
    @classmethod
    def emails_normalized(cls, v: list[str]) -> list[str]:
        """Lower-case each entry and reject anything that is not an email."""
        normalized: list[str] = []
        for raw in v:
            email = raw.strip().lower()
            local, sep, domain = email.partition("@")
            if not sep or not local or "." not in domain:
                raise ValueError(
                    f"allowed_emails entry {raw!r} is not an email address"
                )
            normalized.append(email)
        return normalized

    @model_validator(mode="after")
    def allowlist_required_when_enabled(self) -> OAuthConfig:
        """A profile that turns OAuth on must name who may use it."""
        if self.enabled and not self.allowed_emails:
            raise ValueError(
                "oauth.enabled is true but allowed_emails is empty — refusing "
                "to expose an OAuth seat open to any Google account"
            )
        return self


    @field_validator("allowed_redirect_uris")
    @classmethod
    def redirect_uris_are_exact_https_urls(cls, v: list[str]) -> list[str]:
        """Refuse wildcards and anything that is not a plain https URL.

        The gateway matches these with fnmatch, so a `*` anywhere is a pattern
        rather than a URL. That is fine for the built-in loopback entries and
        dangerous for anything else: gemini.google.com hands every Google user
        a callback under `oauth-redirect.googleusercontent.com/r/`, so allowing
        that prefix would let an attacker register THEIR user-bound callback and
        receive an authorization code meant for this gateway's operator. The
        operator's own URL differs only in the account id at the end, so an
        exact entry blocks every other one on the same host.

        http is refused outright. Loopback is already covered by the built-in
        defaults, and a non-loopback http callback would carry the code in
        clear text.
        """
        cleaned: list[str] = []
        for raw in v:
            uri = raw.strip()
            if "*" in uri or "?" in uri:
                raise ValueError(
                    f"allowed_redirect_uris entry {uri!r} contains a wildcard; "
                    "list the exact callback URL instead — a pattern here would "
                    "also match a callback an attacker registered on the same host"
                )
            if not uri.startswith("https://"):
                raise ValueError(
                    f"allowed_redirect_uris entry {uri!r} must be an https URL "
                    "(loopback clients are already allowed by default)"
                )
            if "#" in uri:
                raise ValueError(
                    f"allowed_redirect_uris entry {uri!r} must not carry a fragment"
                )
            cleaned.append(uri)
        return cleaned

class Profile(BaseModel):
    """One consumer profile: name, auth, backends, defense config."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Profile name (URL-safe slug)")
    auth: AuthConfig | None = Field(
        default=None,
        description=(
            "Static bearer token config. Optional since 0.15.0: a profile "
            "authenticated by OAuth alone omits it. See the model validator — "
            "a profile with no authentication at all is refused."
        ),
    )
    backends: dict[str, Backend] = Field(
        default_factory=dict,
        description="Backend MCP servers reachable from this profile",
    )
    llm_keys: dict[str, LlmKeyOverride] = Field(
        default_factory=dict,
        description=(
            "Per-provider API key overrides for the LLM proxy, keyed by "
            "provider name (must match a configured llm_providers entry)."
        ),
    )
    role: ProfileRole = Field(
        default="agent",
        description=(
            "What this profile may see and act on through the gateway's own "
            "admin tools. 'agent' (the default) is self-scope: its own audit "
            "rows, its own backends, its own section of profiles.yaml. "
            "'operator' is the seat that holds the whole gateway."
        ),
    )
    defense: DefenseConfig = Field(default_factory=DefenseConfig)
    preprocess: PreProcessConfig = Field(
        default_factory=PreProcessConfig,
        description=(
            "Profile-level response reduction policy. Off by default: a "
            "gateway that starts quietly rewriting payloads is not a "
            "default anyone opted into."
        ),
    )
    alert_ingress: AlertIngressConfig | None = Field(
        default=None,
        description="Alert webhook ingress configuration (optional)",
    )
    matrix_ingress: MatrixIngressConfig | None = Field(
        default=None,
        description="Matrix reverse-proxy access for this profile (optional)",
    )
    oauth: OAuthConfig | None = Field(
        default=None,
        description="Google-backed OAuth access for this profile (optional)",
    )

    @field_validator("name")
    @classmethod
    def name_matches_re(cls, v: str) -> str:
        """Profile name must be a URL-safe slug (matches PROFILE_NAME_RE)."""
        if not PROFILE_NAME_RE.match(v):
            raise ValueError(f"Profile name {v!r} must match ^[a-z][a-z0-9-]*$")
        return v

    @field_validator("backends")
    @classmethod
    def backend_names_match_re(cls, v: dict[str, Backend]) -> dict[str, Backend]:
        """Each backend dict key must be a URL-safe slug (matches BACKEND_NAME_RE)."""
        for name in v:
            if not BACKEND_NAME_RE.match(name):
                raise ValueError(f"Backend name {name!r} must match ^[a-z][a-z0-9-]*$")
        return v

    @field_validator("llm_keys")
    @classmethod
    def llm_key_names_match_re(
        cls, v: dict[str, LlmKeyOverride]
    ) -> dict[str, LlmKeyOverride]:
        """Each llm_keys dict key must be a provider slug (matches PROVIDER_NAME_RE).

        Cross-validation against configured llm_providers happens at wiring time
        in register_llm_routes (the provider list is not available here).
        """
        for name in v:
            if not PROVIDER_NAME_RE.match(name):
                raise ValueError(f"Provider name {name!r} must match ^[a-z][a-z0-9-]*$")
        return v

    @model_validator(mode="after")
    def profile_has_an_authentication_method(self) -> Profile:
        """Refuse a profile nothing authenticates.

        Until 0.15.0 `auth` was required, so every profile carried a static
        bearer token and this property held by accident. That had a cost: the
        only way to add OAuth to a seat was to ALSO give it a permanent
        anonymous credential which, because the bearer is checked first,
        bypassed the OAuth entirely — the opposite of what an operator adding
        OAuth believes they are doing.

        So the requirement is now what it always meant: at least one way to
        authenticate, of any kind. A bearer-only agent, an OAuth-only web seat,
        or both together are all valid; neither is not.
        """
        if self.auth is not None:
            return self
        if self.oauth is not None and self.oauth.enabled:
            return self
        raise ValueError(
            f"profile {self.name!r} has no authentication: set auth.bearer_token_env, "
            "or oauth.enabled with allowed_emails, or both. A profile with "
            "neither would serve its backends to anyone who found the URL"
        )
