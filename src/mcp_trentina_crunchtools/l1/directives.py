"""Stage 6: Directive detection — count visible LLM instruction patterns.

Detects lines containing common prompt injection directives: instruction
overrides, privileged-mode requests, prompt extraction, role manipulation,
jailbreaks, safety bypasses and spoofed role tags. Operates on visible text,
complementing the invisible-character stripping (unicode stage) and
special-token stripping (delimiter stage).

Where the patterns come from (#201): OpenRouter's published prompt-injection
guardrail, which is derived from the OWASP LLM Prompt Injection Prevention
Cheat Sheet. They see a great deal of injection traffic, and their list is
field experience. Names follow theirs, so a detection here can be looked up
there. ``l1/evasion.py`` adds their evasion handling (scrambles, typos,
character spacing) on top of the exact patterns.

This stage DETECTS and does not modify. It used to remove the whole line
around a match, which destroyed exactly the content an ops agent exists to
read: a CVE ticket, a Nagios alert, or a security mail *discusses* attacks
in the same words attacks use, and a one-line Jira description containing
"ignore previous instructions" came back as an empty string — silently, with
L2 and L3 left judging the void. Every other stage excises a precise token
(a zero-width character, an encoded blob, a delimiter); this one amputated
prose. Now the count feeds the L1 risk verdict and the sidecar, and the
mode — not this stage — decides whether flagged content reaches the agent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .evasion import collapsed_spacing, corrected_line, scrambled_with_company

_I = re.IGNORECASE
_TARGETS = r"(?:instructions?|rules?|guidelines?|constraints?|directives?)"
_POSSESSIVE = r"(?:your?|yoru|yuor|the|my|its|his|her|our|their)"
_SYSTEM = r"(?:system|systme|sysetm|systemp?)"

#: Every exact pattern, by OpenRouter's name. A line matching any of them is
#: one detection, however many match.
PATTERNS: dict[str, re.Pattern[str]] = {
    name: re.compile(regex, flags)
    for name, regex, flags in [
        # -- instruction override
        (
            "ignore_previous_instructions",
            r"ignore\s+(?:all\s+)?(?:previous|prior)\s+(?:(?:safety|security|system|"
            r"operational|internal|core|original|initial|existing|given|stated|"
            r"provided|defined|specified|established)\s+)?" + _TARGETS,
            _I,
        ),
        ("ignore_all_instructions", r"ignore\s+all\s+instructions", _I),
        (
            "disregard_instructions",
            r"disregard\s+(?:all\s+)?(?:previous|prior|above)\s+" + _TARGETS,
            _I,
        ),
        (
            "forget_instructions",
            r"forget\s+(?:all\s+)?(?:previous|prior|above)\s+" + _TARGETS,
            _I,
        ),
        ("new_instructions", r"new\s+instructions?:", _I),
        (
            "do_not_follow",
            r"do\s+not\s+follow\s+(?:the\s+)?(?:system|developer|previous|original)",
            _I,
        ),
        (
            "supersede_instructions",
            r"supersedes?\s+(?:all\s+)?(?:prior|previous)\s+" + _TARGETS,
            _I,
        ),
        (
            "void_instructions",
            (
                r"(?:previous|prior)\s+instructions?\s+(?:are|is)\s+"
                r"(?:void|invalid|null|obsolete|cancelled|revoked)"
            ),
            _I,
        ),
        # -- developer / admin mode
        ("developer_mode", r"you\s+are\s+now\s+(?:in\s+)?developer\s+mode", _I),
        ("enter_special_mode", r"enter\s+(?:developer|admin|debug|maintenance)\s+mode", _I),
        ("activate_special_mode", r"activate\s+(?:developer|admin|debug|jailbreak)\s+mode", _I),
        # -- system override
        ("system_override", r"\bsystem\s+override\b", _I),
        ("override_instructions", r"override\s+(?:your\s+)?" + _TARGETS, _I),
        # -- prompt extraction
        (
            "reveal_prompt",
            r"reveal\s+(?:" + _POSSESSIVE + r"\s+)?(?:(?:full|hidden|complete|internal|"
            r"secret|original|entire|exact|actual|real)\s+){0,2}(?:" + _SYSTEM + r"\s+)?prompt\b",
            _I,
        ),
        (
            "show_prompt",
            r"show\s+(?:me\s+)?" + _POSSESSIVE + r"\s+(?:" + _SYSTEM + r"\s+)?prompt\b",
            _I,
        ),
        # `the` as well as `your`: OWASP's own test case asks "what were the
        # exact instructions you were given", which OpenRouter's form misses.
        (
            "what_instructions",
            r"what\s+(?:are|were)\s+(?:your\s+|the\s+)?(?:exact\s+)?instructions",
            _I,
        ),
        (
            "repeat_instructions",
            r"repeat\s+(?:the\s+)?(?:text|instructions?)\s+(?:above|before)",
            _I,
        ),
        (
            "output_prompt",
            r"output\s+(?:your\s+)?(?:initial|original|system)\s+(?:prompt|instructions?)",
            _I,
        ),
        ("system_prompt_label", r"system\s+prompt\s*:", _I),
        # -- role manipulation
        ("remove_restrictions", r"you\s+are\s+no\s+longer\s+(?:bound|restricted|limited)", _I),
        ("act_unbound", r"act\s+as\s+if\s+(?:you(?:'re|\s+are)\s+)?not\s+bound", _I),
        (
            "pretend_different",
            r"pretend\s+(?:you(?:'re|\s+are)\s+)?(?:a\s+)?different\s+(?:ai|assistant|model)",
            _I,
        ),
        # Replaced the bare `you are now a\b` (#201), which fired on "you are
        # now a member of the group". A hijack needs its malicious modifier.
        (
            "identity_hijack",
            (
                r"you\s+are\s+now\s+(?:(?:a|an)\s+)?\w+.{0,40}(?:without\s+(?:any\s+)?restrict|"
                r"ignor\w*\s+(?:all|any|every|prev)|bypass|unrestrict|unlimit|obey\s+only|"
                r"no\s+(?:rules|limits|restrict|boundari))"
            ),
            _I,
        ),
        ("new_role", r"your\s+new\s+role\s+is\b", _I),
        ("as_an_ai_you_must", r"as\s+an\s+ai\s*,?\s+you\s+must", _I),
        # -- DAN / jailbreak. DAN is case-sensitive: "dan" is a name.
        ("dan_jailbreak", r"\bDAN\b.*\b[Dd]o\s+[Aa]nything\s+[Nn]ow\b", 0),
        ("jailbreak_mode", r"jailbreak(?:ed)?\s+(?:mode|prompt)", _I),
        # -- safety bypass
        (
            # `override` and `settings` beyond OpenRouter's, for OWASP's
            # "override your security settings". The qualifier is still
            # required, so "override your settings" in a config guide is not.
            "bypass_safety",
            (
                r"(?:bypass|override)\s+(?:your\s+)?(?:safety|security|content|ethical)\s+"
                r"(?:filters?|measures?|guidelines?|restrictions?|settings?)"
            ),
            _I,
        ),
        (
            "disable_safety",
            r"disable\s+(?:your\s+)?(?:safety|security|content)\s+(?:filters?|measures?)",
            _I,
        ),
        (
            "ignore_safety",
            (
                r"(?:ignore|disregard)\s+(?:all\s+)?(?:your\s+)?(?:safety|security|ethical|content)\s+"
                r"(?:guidelines?|rules?|restrictions?|measures?|filters?|polic(?:y|ies)|protocols?)"
            ),
            _I,
        ),
        # -- tag injection and role spoofing
        ("system_tag_injection", r"<\s*(?:/\s*)?system\s*/?>", _I),
        (
            # Narrower than OpenRouter's, which fires on the `<tool>` in
            # `<backend>__<tool>` and every usage line that names one: an
            # opening tag must start the line, and a closing or self-closing
            # one counts anywhere, since no placeholder is written that way.
            "role_tag_injection",
            (
                r"^\s*<\s*(?:assistant|developer|tool|function)\s*/?>"
                r"|<\s*/\s*(?:assistant|developer|tool|function)\s*>"
                r"|<\s*(?:assistant|developer|tool|function)\s*/>"
            ),
            _I,
        ),
        (
            "bracketed_role_spoofing",
            r"\[\s*(?:System\s*Message|System|Assistant|Internal)\s*\]",
            _I,
        ),
        # Capital S only, unlike OpenRouter's: `system: ` opens ordinary log
        # and config lines, and an impersonated system turn is written the
        # way the real one is.
        ("system_prefix_spoofing", r"^\s*System:\s+", 0),
        # -- command execution
        ("execute_the_following", r"execute\s+the\s+following", _I),
        ("run_this_command", r"run\s+this\s+command", _I),
    ]
}

_PREFIX_PATTERNS = re.compile(
    r"^\s*(?:IMPORTANT|INSTRUCTION|OVERRIDE|ADMIN)\s*:",
    re.IGNORECASE,
)

# `]` closing one line and a role label opening the next: `...]\n[system]:`.
# The only pattern that needs the previous line, so it is checked in the loop.
_ROLE_LABEL = re.compile(r"^\s*\[?(?:system|assistant|user)\]?:", re.IGNORECASE)


@dataclass
class DirectiveStats:
    """Statistics from directive detection.

    The two are disjoint: ``evasions_detected`` counts the lines that matched
    only once ``l1/evasion.py`` undid a scramble, a typo or character spacing,
    and those lines are not in ``directives_detected``. Both feed risk, which
    sums every field.
    """

    directives_detected: int = 0
    evasions_detected: int = 0


def matches_exact(line: str) -> bool:
    """Whether ``line`` matches the prefix rule or any exact pattern."""
    return bool(_PREFIX_PATTERNS.search(line)) or any(p.search(line) for p in PATTERNS.values())


def _matches_evasion(line: str) -> bool:
    """Whether ``line`` is an injection once its evasion is undone."""
    if scrambled_with_company(line):
        return True
    collapsed = collapsed_spacing(line)
    if collapsed is not None and matches_exact(collapsed):
        return True
    for candidate in (line, collapsed):
        if candidate is None:
            continue
        corrected = corrected_line(candidate)
        if corrected is not None and matches_exact(corrected):
            return True
    return False


def strip_directives(text: str) -> tuple[str, DirectiveStats]:
    """Count lines containing LLM directive patterns; return text unchanged.

    One detection per line, however many patterns hit it — the unit of
    suspicion is the hostile line, and counting each pattern would let a
    single line inflate the risk score on its own.
    """
    stats = DirectiveStats()

    previous = ""
    for line in text.split("\n"):
        if matches_exact(line) or (previous.rstrip().endswith("]") and _ROLE_LABEL.search(line)):
            stats.directives_detected += 1
        elif _matches_evasion(line):
            stats.evasions_detected += 1
        previous = line

    return text, stats
