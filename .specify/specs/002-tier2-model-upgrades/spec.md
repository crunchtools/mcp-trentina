# Specification: Tier 2 Model Upgrades

> **Spec ID:** 002-tier2-model-upgrades
> **Status:** Draft
> **Version:** 0.1.0
> **Author:** Scott McCarty
> **Date:** 2026-03-10

## Overview

Model-level improvements to the Q-Agent's detection accuracy and output safety.
Upgrades the default model from Gemini 2.0 Flash-Lite to 2.5 Flash-Lite (adversarial
training), and constrains the Q-Agent response schema to minimize free-text attack
surface. Builds on Tier 1 post-extraction sanitization (spec 001).

---

## Items

### 1. Upgrade default Q-Agent model

Change `DEFAULT_MODEL` from `gemini-2.0-flash-lite` to `gemini-2.5-flash-lite`.

Gemini 2.5 Flash-Lite has dedicated adversarial training against indirect prompt
injection ($0.075 -> $0.10/M input tokens). The `QUARANTINE_MODEL` env var override
is preserved for users who want a different model.

**Files:** `config.py`

### 2. Add `maxLength` constraints to response schemas

Constrain all free-text fields in both response schemas to limit the output surface
a compromised Q-Agent can use:

**Extraction schema:**
| Field | maxLength | Rationale |
|-------|-----------|-----------|
| `extracted_text` | 50000 | Primary attack surface — cap at 50K chars |
| `title` | 500 | Page titles should be short |
| `injection_details` | 2000 | Sufficient for finding descriptions |

**Detection schema:**
| Field | maxLength | Rationale |
|-------|-----------|-----------|
| `summary` | 2000 | Brief summary of scan results |
| `findings[].type` | 200 | Injection vector type label |
| `findings[].description` | 1000 | Individual finding description |

**Files:** `quarantine/prompts.py`

### 3. Add directive stripping as a new sanitization pipeline stage

Add a new `sanitize/directives.py` module — a new stage in the sanitization pipeline
that strips visible English-language LLM instruction patterns. Follows the same
pattern as the existing stages (unicode, encoded, exfiltration, delimiters):
- `DirectiveStats` dataclass with a `directives_stripped` count field
- `sanitize_directives(text)` function returning `(cleaned_text, DirectiveStats)`
- Added to `PipelineStats` in `pipeline.py`
- Called in both `sanitize()` and `sanitize_text()` as the final stage

This protects **both directions** — content going into the Q-Agent (Layer 1 input
sanitization) and content coming out (post-extraction `sanitize_text()` pass from
Tier 1 item #5). No changes needed to `agent.py` — the existing `sanitize_text()`
call already covers it.

Patterns to strip (case-insensitive, line-level):
- "ignore previous instructions"
- "ignore all instructions"
- "you are now a..."
- "your new role is..."
- "system prompt:"
- "execute the following"
- "run this command"
- "as an AI, you must..."
- Lines starting with imperative AI directives: "IMPORTANT:", "INSTRUCTION:",
  "OVERRIDE:", "ADMIN:"

False positives are acceptable — if legitimate content discusses prompt injection,
stripping those phrases from extracted content is fine. The Q-Agent's job is
factual extraction, not preserving adversarial content verbatim.

Post-extraction chain (unchanged in `agent.py`):
1. `sanitize_text()` now internally handles: unicode → encoded → exfiltration →
   delimiters → **directives**
2. Truncate to `maxLength` (belt + suspenders with Gemini's own schema enforcement)

**New file:** `sanitize/directives.py`
**Modified files:** `sanitize/pipeline.py`

---

## Security Considerations

### Schema Constraints
- Gemini's `responseSchema` with `maxLength` is advisory, not guaranteed — the
  post-extraction truncation in Python is the enforcement layer.
- Schema constraints are defense-in-depth: they guide the model AND we enforce in code.

### Directive Stripping
- Runs as a pipeline stage inside `sanitize_text()` and `sanitize()`, protecting
  both Q-Agent input and output paths with a single implementation.
- Regex-based — operates on visible text. Complements invisible-character stripping
  (unicode stage) and special-token stripping (delimiter stage).
- False positives are acceptable. The `directives_stripped` stat count surfaces in
  Layer 1 stats for monitoring.

### Model Upgrade
- No code change beyond the default string. The REST API endpoint format is identical.
- Fallback: users can override with `QUARANTINE_MODEL=gemini-2.0-flash-lite` if needed.

---

## Module Changes

### New Files

| File | Purpose |
|------|---------|
| `sanitize/directives.py` | Directive stripping stage — `sanitize_directives()` + `DirectiveStats` |

### Modified Files

| File | Changes |
|------|---------|
| `config.py` | Change `DEFAULT_MODEL` to `gemini-2.5-flash-lite` |
| `quarantine/prompts.py` | Add `maxLength` to all free-text schema fields |
| `quarantine/agent.py` | Add post-extraction `maxLength` truncation |
| `sanitize/pipeline.py` | Add `DirectiveStats` to `PipelineStats`, call `sanitize_directives()` in both pipelines |

---

## Testing Requirements

### Model Default Test
- [ ] `test_default_model_is_2_5_flash_lite` — verify `DEFAULT_MODEL` constant

### Schema Constraint Tests (in `test_qagent.py`)
- [ ] `test_extraction_schema_has_max_lengths` — all free-text fields have `maxLength`
- [ ] `test_detection_schema_has_max_lengths` — all free-text fields have `maxLength`

### Directive Stripping Tests (new `test_sanitize_directives.py`)
- [ ] `test_strips_ignore_instructions` — "ignore previous instructions" removed
- [ ] `test_strips_role_reassignment` — "you are now a..." removed
- [ ] `test_strips_imperative_prefixes` — "INSTRUCTION:", "OVERRIDE:" lines removed
- [ ] `test_preserves_normal_content` — regular text passes through unchanged
- [ ] `test_returns_directive_count` — count reflects number of stripped lines
- [ ] `test_case_insensitive` — patterns match regardless of case

### Pipeline Integration Tests (in `test_pipeline.py`)
- [ ] `test_pipeline_includes_directive_stats` — PipelineStats has directives field

### Post-Extraction Truncation Tests (update `TestPostExtractionSanitization` in `test_qagent.py`)
- [ ] `test_output_truncated_to_max_length` — extracted_text capped at 50K

### Existing Tests
- [ ] All 148 existing tests pass without modification

---

## Dependencies

- Depends on: spec 001-tier1-hardening (post-extraction L1 pass)
- Blocks: none

---

## Open Questions

None — items are well-defined from the issue and research session.

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | 2026-03-10 | Initial draft |
| 0.2.0 | 2026-03-10 | Moved directive stripping into sanitize pipeline per review |
