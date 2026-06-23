# Specification: Layer 2 — Prompt Guard 2 Classifier

> **Spec ID:** 003-tier3-layer2-classifier
> **Status:** Draft
> **Version:** 0.3.0
> **Author:** Scott McCarty / Josui
> **Date:** 2026-03-10

## Overview

Add Llama Prompt Guard 2 22M as a dedicated classifier layer (Layer 2) between
deterministic sanitization (Layer 1) and the Gemini Q-Agent (Layer 3). The ONNX
model is embedded directly in the mcp-trentina container image — no sidecar, no
HTTP API, no network calls. In-process inference via ONNX Runtime for minimal
latency. Creates a three-layer defense system where each layer has fundamentally
different failure modes: regex, classifier, and LLM.

---

## License Correction

The issue states "MIT licensed" — this applies to the base DeBERTa-xsmall model
from Microsoft, NOT the Prompt Guard 2 fine-tune. The actual license is **Llama 4
Community License Agreement** (effective April 5, 2025):
- Requires "Built with Llama" attribution
- Must comply with Llama Acceptable Use Policy
- Commercial restrictions for services with >700M MAU (not applicable)
- Redistribution requires including the license agreement

No practical impact on CrunchTools usage, but attribution is required in the
container image and repository.

---

## Architecture

### Embedded ONNX Model

The Prompt Guard 2 22M classifier runs in-process alongside the MCP server.
No sidecar container, no HTTP overhead, no network failure modes.

**Stack:**
- ONNX Runtime for inference (not PyTorch — smaller footprint, faster)
- Model: Own ONNX conversion from `meta-llama/Llama-Prompt-Guard-2-22M` (official Meta weights)
- Tokenizer: `transformers` `AutoTokenizer` (tokenizer files only, no PyTorch model)
- Multi-stage build: PyTorch + optimum export in builder stage, ONNX files only in runtime
- Model files baked into the container image at build time

**Resource impact on the mcp-trentina container:**
- Additional disk: ~100-150MB (ONNX model + runtime)
- Additional memory: ~200-300MB RSS (model loaded in memory)
- Inference latency: ~30-80ms per classification on CPU (4 vCPU lotor)

**Model loading:**
- Lazy-loaded on first classification call (not at server startup)
- Singleton pattern — loaded once, reused across requests
- If model files are missing from the image, classifier is silently unavailable
  (graceful degradation to Layer 1 + Layer 3 only)

**Long input handling:**
Prompt Guard 2 has a 512-token context window. For content longer than 512 tokens,
split into overlapping segments (stride=256), classify each segment, and return
the highest-confidence malicious score across all segments.

**Configuration:**
- `CLASSIFIER_THRESHOLD` env var (default: `0.9`)
- `CLASSIFIER_MODEL_PATH` env var (default: `/models/prompt-guard-2-22m`)

---

## Items

### 1. Create classifier module

New file: `quarantine/classifier.py`

```python
@dataclass
class ClassifierResult:
    label: str          # "BENIGN" or "MALICIOUS"
    score: float        # confidence score (0.0-1.0)
    latency_ms: float   # inference time

def classify(text: str) -> ClassifierResult | None:
    """Run Layer 2 classifier on text.

    Returns ClassifierResult, or None if the model is not available.
    Synchronous — ONNX Runtime inference is CPU-bound, not I/O-bound.
    """

def is_classifier_available() -> bool:
    """Check if the ONNX model is loaded and ready."""
```

Note: `classify()` is synchronous, not async. ONNX inference is CPU-bound work
that completes in <100ms. Wrapping it in async would add complexity for no benefit.
Callers in async tools can call it directly (acceptable for <100ms blocking).

**Segment splitting logic:**
1. Tokenize full text
2. If token count <= 512, classify directly
3. If token count > 512, split into segments of 512 tokens with stride 256
4. Classify each segment
5. Return the result with the highest malicious score

### 2. Update Containerfile

Add ONNX Runtime and model to the existing mcp-trentina container:
- Install `onnxruntime` and `transformers` (tokenizer only) as dependencies
- Download and bake in the quantized ONNX model at build time
- Add "Built with Llama" attribution to container labels

### 3. Integrate into fetch/read/scan pipelines

After Layer 1 sanitization, before Layer 3 Q-Agent:

```
content = sanitize(raw)                   # Layer 1
classification = classify(content)         # Layer 2 (new, in-process)
if classification and classification.label == "MALICIOUS":
    # For safe_fetch/safe_read: block + record_detection
    # For quarantine_fetch/quarantine_read: warn + proceed
    # For quarantine_scan: include in assessment
extraction = await quarantine_extract(...) # Layer 3
```

**Pipeline behavior by tool:**

| Tool | Layer 2 MALICIOUS | Behavior |
|------|-------------------|----------|
| `safe_fetch` / `safe_read` | Block | `record_detection()` + `BlockedSourceError` |
| `quarantine_fetch` / `quarantine_read` | Warn | Add `classifier_warning` to response, proceed |
| `quarantine_scan` / `deep_quarantine_scan` | Report | Include in scan result, contributes to risk |

### 4. Dual-model verification on Q-Agent output

After Layer 3 extraction, run the Q-Agent's `extracted_text` through the
classifier before returning to the P-Agent. This catches cases where the Q-Agent
was compromised and embedded injection patterns in its output.

Post-extraction chain becomes:
1. `sanitize_text()` — strips invisible chars, encoded payloads, delimiters, directives
2. Truncate to `MAX_EXTRACTED_TEXT`
3. `classify()` — Layer 2 checks for injection patterns in output

If the classifier flags the Q-Agent output as MALICIOUS, add a
`classifier_output_warning` to the response.

### 5. Update config and stats

- Add `CLASSIFIER_THRESHOLD` and `CLASSIFIER_MODEL_PATH` to `Config`
- Report classifier availability and model info in `quarantine_stats_tool`

---

## Security Considerations

### Graceful Degradation
- All builds include the ONNX model — three tiers always.
- If the model files are corrupted or fail to load, the classifier returns
  None and the system falls back to Layer 1 + Layer 3 only.
- No crashes, no errors — just reduced defense depth as a safety net.

### Classifier Limitations
- 512-token context window — requires segment splitting for longer content.
  An attacker could spread injection across segment boundaries. The overlapping
  stride (256 tokens) mitigates this but doesn't eliminate it.
- English-focused — the 22M model has reduced accuracy on non-English content.
  Layer 1 and Layer 3 provide coverage for multilingual attacks.
- Binary classification only — no risk gradation. Complements Layer 1 risk levels
  and Layer 3 Q-Agent findings.

### Supply Chain
- Own ONNX conversion from official Meta PyTorch weights — no community
  intermediary in the supply chain.
- Model files are downloaded at container build time and baked into the image.
- Verify checksums of ONNX model files in the Containerfile.
- Requires `HF_TOKEN` at build time to download from `meta-llama/` (not
  baked into the final image).

### In-Process Trust
- The classifier runs in the same process as the MCP server. It has no tools,
  no network access, and no ability to take actions — it just returns a
  classification result.
- It sees sanitized content (post-Layer 1) on the input path, reducing exposure
  to adversarial inputs. Exception: `deep_quarantine_scan` sends raw content.

---

## Module Changes

### New Files

| File | Purpose |
|------|---------|
| `quarantine/classifier.py` | ONNX model loader, tokenizer, segment splitter, `classify()` function |

### Modified Files

| File | Changes |
|------|---------|
| `config.py` | Add `CLASSIFIER_THRESHOLD`, `CLASSIFIER_MODEL_PATH` |
| `Containerfile` | Add ONNX Runtime, transformers, model download |
| `pyproject.toml` | Add `onnxruntime`, `transformers`, `optimum` dependencies |
| `tools/fetch.py` | Call classifier after Layer 1, before Layer 3 |
| `tools/read.py` | Call classifier after Layer 1, before Layer 3 |
| `tools/scan.py` | Include classifier result in scan assessment |
| `tools/stats.py` | Report classifier availability |
| `quarantine/agent.py` | Dual-model verification on Q-Agent output |

---

## Testing Requirements

### Classifier Module Tests (`test_classifier.py`)
- [ ] `test_classify_malicious` — known injection text returns MALICIOUS
- [ ] `test_classify_benign` — clean text returns BENIGN
- [ ] `test_classify_model_not_available` — returns None when model missing
- [ ] `test_segment_splitting` — long text split into overlapping segments
- [ ] `test_highest_score_wins` — segment with highest malicious score returned

### Pipeline Integration Tests
- [ ] `test_safe_fetch_blocks_on_classifier_malicious`
- [ ] `test_quarantine_fetch_warns_on_classifier_malicious`
- [ ] `test_scan_includes_classifier_result` — scan result has layer2 section
- [ ] `test_graceful_degradation` — pipeline works when classifier unavailable

### Dual-Model Verification Tests
- [ ] `test_output_verification_clean` — clean Q-Agent output passes
- [ ] `test_output_verification_malicious` — flagged output gets warning

### Stats Tests
- [ ] `test_stats_reports_classifier_availability`

### Existing Tests
- [ ] All 162 existing tests pass

---

## Dependencies

- Depends on: spec 001-tier1-hardening, spec 002-tier2-model-upgrades
- New Python deps: `onnxruntime`, `transformers`, `optimum[onnxruntime]`
- Model: Own ONNX conversion from `meta-llama/Llama-Prompt-Guard-2-22M`

---

## Resolved Questions

1. **Threshold tuning:** Start at 0.9 default. Write a calibration script (dev
   tool, not unit test) that runs known-good and known-bad corpora through the
   classifier and prints score distributions. Adjust once based on real data.
   The `CLASSIFIER_THRESHOLD` env var allows per-deployment tuning.

2. **ONNX source:** Own conversion from the official Meta PyTorch model
   (`meta-llama/Llama-Prompt-Guard-2-22M`) for full supply chain control.
   Multi-stage Containerfile: Stage 1 installs PyTorch + optimum + transformers
   to export ONNX, Stage 2 copies only the ONNX files into the runtime image.
   Requires `HF_TOKEN` at build time (not baked into final image).

3. **Always three tiers:** The model is always included in every build. No
   lightweight/optional builds. Graceful degradation code remains as a safety
   net (corrupted model, etc.) but the Containerfile always builds with the
   full ONNX model.

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | 2026-03-10 | Initial draft (sidecar architecture) |
| 0.2.0 | 2026-03-10 | Embedded ONNX in-process, no sidecar per review |
| 0.3.0 | 2026-03-10 | Resolved open questions: 0.9 threshold + calibrate, own ONNX conversion, always three tiers |
