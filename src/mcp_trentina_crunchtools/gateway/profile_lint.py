"""Posture lint for profiles.yaml (#269, from the #90 audit).

The loader decides whether a profiles file is VALID. This decides whether it
is SAFE, in three ways the #90 audit found live:

- ``shared-write-backend``: two profiles reach the same backend URL and both
  hold a write tool on it. Whatever one writes the other can read, which is a
  message board between agents unless someone decided it should be one. That
  decision is recorded in an optional top-level ``shared_backends`` list,
  which the loader ignores::

      shared_backends:
        - url: "http://mcp-memory:8000/mcp"
          profiles: [kagetora, takeda]
          reason: "shared memory is the point of this pair (RT #1234)"

- ``toxic-flow``: one seat holds open fetch, a public inbox (alert ingress or
  Matrix) and an outbound-comms tool with no parameter guard. Untrusted input
  arrives, instructions can be fetched, and something can be sent out: the
  incident's shape in one profile.
- ``require-default-open``: a ``TRENTINA_REQUIRE_*`` switch whose default is
  not fail-closed.

Tool names are judged from the allowlist alone, because the lint runs without
the backends. A wildcard counts as holding whatever it could admit: a glob that
admits a write tool the backend adds next month holds it already.

    python -m mcp_trentina_crunchtools.gateway.profile_lint /config/profiles.yaml

exits 1 with one line per finding, 0 when clean, 2 when the file cannot be read.
"""

from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass
from fnmatch import fnmatchcase
from itertools import combinations
from pathlib import Path
from typing import Any

import yaml

#: A leading token that makes a tool a write: create_issue, memory_store, deletePostTool.
WRITE_VERBS = frozenset(
    {
        "add", "append", "approve", "assign", "batch", "cancel", "complete", "copy", "create",
        "delete", "deploy", "disable", "dispatch", "draft", "edit", "enable", "import",
        "ingest", "insert", "log", "manage", "mark", "mask", "merge", "modify", "move",
        "post", "promote", "prune", "publish", "pull", "purge", "reject", "reload", "remove",
        "rename", "reorder", "reply", "request", "rerun", "reset", "resolve", "restart",
        "retry", "run", "save", "schedule", "send", "set", "source", "start", "stop", "store",
        "tag", "take", "teardown", "toggle", "transition", "trigger", "unmask", "update",
        "upload", "upsert", "write",
    }
)  # fmt: skip

#: A leading token that makes a tool outbound communication on its own.
OUTBOUND_VERBS = frozenset(
    {"send", "post", "reply", "publish", "notify", "share", "forward", "dispatch", "schedule"}
)

#: With a write verb, these make it outbound: create_post, add_ticket_comment.
COMMS_NOUNS = frozenset(
    {"post", "posts", "comment", "message", "messages", "mail", "email", "reply", "tweet",
     "webhook", "ticket", "page", "media"}
)  # fmt: skip

#: A first token that makes a tool read-only whatever follows.
READ_VERBS = frozenset(
    {"get", "list", "search", "read", "query", "fetch", "show", "describe", "status", "find",
     "analyze", "count", "view", "check", "inspect", "lookup", "whoami"}
)  # fmt: skip

#: Tokens that fill a wildcard to ask what a glob could admit.
_FILLERS = tuple(
    fill
    for verb in sorted(WRITE_VERBS | OUTBOUND_VERBS)
    for fill in (verb, f"{verb}_x", f"x_{verb}", f"{verb}_message", f"{verb}_post")
)

_TOKEN_RE = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])")
_REQUIRE_RE = re.compile(r"^TRENTINA_REQUIRE_[A-Z0-9_]+$")
FETCH_TOOL = "fetch_tool"
INTERNAL_SCHEME = "internal://"


@dataclass(frozen=True)
class Finding:
    """One posture problem. Every name in it comes from the operator's file."""

    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


def tokens(name: str) -> list[str]:
    """``personal_send_gmail_message`` and ``integrationSchedulePostTool`` as lowercase words."""
    return [t.lower() for part in name.split("_") for t in _TOKEN_RE.findall(part)]


def classify(name: str) -> set[str]:
    """``{"write"}``, ``{"write", "outbound"}``, or nothing, from the name alone.

    The verb is looked for in the first two words, so a namespace prefix
    (``github_create_issue``, ``memory_store``) still counts and a noun later
    in the name (``crunch_get_post``) does not.
    """
    words = tokens(name)
    if not words or words[0] in READ_VERBS:
        return set()
    head = words[:2]
    kinds: set[str] = set()
    if any(w in WRITE_VERBS for w in head):
        kinds.add("write")
    if any(w in OUTBOUND_VERBS for w in head) or (
        "write" in kinds and any(w in COMMS_NOUNS for w in words)
    ):
        kinds.add("outbound")
    return kinds


def _admits(backend: dict[str, Any], name: str) -> bool:
    allow = backend.get("tools_allow", ["*"])
    deny = backend.get("tools_deny") or []
    return any(fnmatchcase(name, p) for p in allow) and not any(fnmatchcase(name, p) for p in deny)


def held_tools(backend: dict[str, Any]) -> dict[str, set[str]]:
    """Each allow pattern that holds a write or outbound tool, and which kinds.

    A literal is judged by its name. A glob is filled with synthetic names and
    judged by the ones it would admit past ``tools_deny``.
    """
    held: dict[str, set[str]] = {}
    for pattern in backend.get("tools_allow", ["*"]):
        if not any(c in pattern for c in "*?["):
            candidates: tuple[str, ...] = (pattern,)
        else:
            candidates = tuple(pattern.replace("*", fill).replace("?", "x") for fill in _FILLERS)
        kinds: set[str] = set()
        for name in candidates:
            if fnmatchcase(name, pattern) and _admits(backend, name):
                kinds |= classify(name)
        if kinds:
            held[pattern] = kinds
    return held


def _constrains(guard: dict[str, Any]) -> bool:
    """A parameter guard that narrows something: an allow list with no catch-all.

    ``allow: ["*"]`` admits every value, and a deny list admits everything it
    did not think of, so neither makes a tool guarded.
    """
    for constraint in guard.values():
        allow = (constraint or {}).get("allow") or []
        if allow and not any(set(p) <= set("*?") for p in allow):
            return True
    return False


def _guarded(backend: dict[str, Any], pattern: str) -> bool:
    """A literal tool whose guard narrows it. A glob never is: guards key on exact names."""
    if any(c in pattern for c in "*?["):
        return False
    return _constrains((backend.get("parameter_guards") or {}).get(pattern) or {})


def _profiles(profiles_file: dict[str, Any]) -> dict[str, dict[str, Any]]:
    profiles = profiles_file.get("profiles") or {}
    return {str(name): body or {} for name, body in profiles.items()}


def _allowances(profiles_file: dict[str, Any]) -> list[tuple[str, frozenset[str]]]:
    found: list[tuple[str, frozenset[str]]] = []
    for entry in profiles_file.get("shared_backends") or []:
        if not isinstance(entry, dict) or not str(entry.get("reason", "")).strip():
            continue  # an allowance with no reason is not a decision
        found.append((str(entry.get("url", "")), frozenset(map(str, entry.get("profiles", [])))))
    return found


def check_shared_write_backends(profiles_file: dict[str, Any]) -> list[Finding]:
    """Two profiles holding write tools on one backend URL, with no allowance."""
    writers: dict[str, dict[str, str]] = {}
    for profile, body in _profiles(profiles_file).items():
        for backend_name, backend in (body.get("backends") or {}).items():
            url = str(backend.get("url", "")).rstrip("/")
            if url.startswith(INTERNAL_SCHEME):
                continue  # in-process, per profile; the shared state inside is #263's
            if any("write" in kinds for kinds in held_tools(backend).values()):
                writers.setdefault(url, {})[profile] = str(backend_name)
    allowed = _allowances(profiles_file)
    findings = []
    for url, holders in sorted(writers.items()):
        for a, b in combinations(sorted(holders), 2):
            if any(u.rstrip("/") == url and {a, b} <= ps for u, ps in allowed):
                continue
            findings.append(
                Finding(
                    "shared-write-backend",
                    f"profiles {a!r} ({holders[a]}) and {b!r} ({holders[b]}) both hold write "
                    f"tools on {url}; declare the pair under shared_backends with a reason, "
                    "or cut the write tools from one of them",
                )
            )
    return findings


def _open_fetch(body: dict[str, Any]) -> str | None:
    for name, backend in (body.get("backends") or {}).items():
        if not str(backend.get("url", "")).startswith(INTERNAL_SCHEME):
            continue
        if not _admits(backend, FETCH_TOOL):
            continue
        guard = (backend.get("parameter_guards") or {}).get(FETCH_TOOL) or {}
        if not _constrains({"url": guard.get("url")}):
            return str(name)
    return None


def _public_inbox(body: dict[str, Any]) -> str | None:
    for key in ("alert_ingress", "matrix_ingress", "matrix_bridge"):
        if body.get(key):
            return key
    return None


def _unguarded_outbound(body: dict[str, Any]) -> list[str]:
    found = []
    for name, backend in (body.get("backends") or {}).items():
        if str(backend.get("url", "")).startswith(INTERNAL_SCHEME):
            continue  # Trentina's own tools; fetch is the open-fetch leg, and none sends
        for pattern, kinds in held_tools(backend).items():
            if "outbound" in kinds and not _guarded(backend, pattern):
                found.append(f"{name}:{pattern}")
    return found


def check_toxic_flows(profiles_file: dict[str, Any]) -> list[Finding]:
    """A seat with open fetch, a public inbox and an unguarded outbound tool together."""
    findings = []
    for profile, body in _profiles(profiles_file).items():
        fetch, inbox, outbound = _open_fetch(body), _public_inbox(body), _unguarded_outbound(body)
        if fetch and inbox and outbound:
            findings.append(
                Finding(
                    "toxic-flow",
                    f"profile {profile!r} holds open fetch ({fetch}), a public inbox ({inbox}) "
                    f"and unguarded outbound tools ({', '.join(sorted(outbound))}); guard the "
                    "outbound tools, guard fetch_tool's url, or drop one of the three",
                )
            )
    return findings


def check_require_defaults(source: str | None = None) -> list[Finding]:
    """Every ``TRENTINA_REQUIRE_*`` read from the environment defaults to fail-closed.

    Reads ``config.py``: a ``bool_env("TRENTINA_REQUIRE_X", <default>)`` whose
    default is anything but the literal ``True`` is a finding, and so is an
    ``os.environ.get``/``getenv`` of one, which has no typed default at all.
    """
    if source is None:
        source = (Path(__file__).resolve().parent.parent / "config.py").read_text()
    findings = []
    seen = 0
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        # Positional or keyword: bool_env(name, default) and getenv(key=...) alike.
        passed = [*node.args, *(kw.value for kw in node.keywords if kw.arg is not None)]
        named = {kw.arg: kw.value for kw in node.keywords if kw.arg is not None}
        switches = [
            a.value
            for a in passed
            if isinstance(a, ast.Constant)
            and isinstance(a.value, str)
            and _REQUIRE_RE.match(a.value)
        ]
        if not switches:
            continue
        seen += 1
        callee = ast.unparse(node.func)
        default = node.args[1] if len(node.args) > 1 else named.get("default")
        closed = (
            callee.endswith("bool_env")
            and isinstance(default, ast.Constant)
            and default.value is True
        )
        if not closed:
            findings.append(
                Finding(
                    "require-default-open",
                    f"{switches[0]} is read by {callee}() with default "
                    f"{ast.unparse(default) if default is not None else 'none'}; "
                    "it must be bool_env(..., True)",
                )
            )
    if not seen:
        findings.append(
            Finding("require-default-open", "no TRENTINA_REQUIRE_* switch found in config.py")
        )
    return findings


def lint(profiles_file: dict[str, Any], *, config_source: str | None = None) -> list[Finding]:
    """Every posture finding for a parsed profiles file."""
    return [
        *check_shared_write_backends(profiles_file),
        *check_toxic_flows(profiles_file),
        *check_require_defaults(config_source),
    ]


def lint_file(path: Path | str) -> list[Finding]:
    """Lint the profiles file at ``path``. Raises OSError or yaml.YAMLError if unreadable."""
    profiles_file = yaml.safe_load(Path(path).read_text())
    if not isinstance(profiles_file, dict):
        raise yaml.YAMLError(f"{path}: not a mapping")
    return lint(profiles_file)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m mcp_trentina_crunchtools.gateway.profile_lint <profiles.yaml>")
        return 2
    try:
        findings = lint_file(args[0])
    except (OSError, yaml.YAMLError) as exc:
        # The operator's own terminal, not the gateway's journal: the parser's
        # line and cause are what fixes the file.
        print(f"profile_lint: cannot read {args[0]}: {exc}", file=sys.stderr)
        return 2
    for finding in findings:
        print(finding)
    print(f"{len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
