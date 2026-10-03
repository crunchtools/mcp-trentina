# MCP Trentina CrunchTools Container
# Three-layer defense: deterministic checks + a local classifier (L2) + quarantined LLM
# Built entirely on Hummingbird Python images (Red Hat hardened, minimal)
#
# Build: the GHA pipeline, and only the GHA pipeline.
# .github/workflows/container.yml builds and pushes quay.io/crunchtools/mcp-trentina.
# Do NOT build this image by hand — building outside the pipeline causes drift.
#
# The model-builder stage below needs HF_TOKEN to reach the GATED Meta Prompt Guard
# repo (one of the two L2 models; the default, Horizon-Labs', is ungated). That credential belongs in GitHub secrets and nowhere else; it must never be
# copied to a workstation, because no local build path legitimately needs it.
#
# GitHub keeps Actions secrets and Dependabot secrets in SEPARATE stores, and a run
# triggered by Dependabot reads only the Dependabot store. HF_TOKEN must therefore
# exist in BOTH, or every dependency-update PR fails right here with a 401 on a gated
# repo while main stays green. Symptom to look for in the log: `--build-arg HF_TOKEN=`
# with nothing after the `=`. On crunchtools the Dependabot secret must be set at REPO
# level; an org-level Dependabot secret did not reach the build.
#
# Run (Streamable HTTP on port 8019):
#   podman run --rm \
#     --env-file ~/.config/mcp-env/mcp-trentina.env \
#     -v ~/.local/share/mcp-trentina:/data:Z \
#     -p 127.0.0.1:8019:8019 \
#     quay.io/crunchtools/mcp-trentina \
#     --transport streamable-http --host 0.0.0.0 --port 8019
#
# Optional D-Bus integration (for Cockpit plugin / mcp-assayer):
#   Add: -v /run/dbus/system_bus_socket:/run/dbus/system_bus_socket:z
#   D-Bus is optional — the server runs fine without it (--no-dbus is implicit
#   when the socket is not mounted).
#
# With Claude Code (stdio):
#   claude mcp add mcp-trentina-crunchtools \
#     -- podman run -i --rm \
#     --env-file ~/.config/mcp-env/mcp-trentina.env \
#     -v ~/.local/share/mcp-trentina:/data:Z \
#     quay.io/crunchtools/mcp-trentina

# ============================================================
# Stage 1: ONNX model conversion (Hummingbird builder — discarded)
# Builder variant includes DNF for installing libstdc++ and
# other native deps needed by PyTorch/numpy ONNX conversion.
# ============================================================
FROM quay.io/hummingbird/python:latest-builder AS model-builder
USER 0

RUN pip install --no-cache-dir \
    torch --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir \
    optimum[onnxruntime] \
    transformers \
    sentencepiece

# Both L2 models, each exported to ONNX from a PINNED revision of its
# safetensors, with the trentina-model.json manifest the classifier reads
# for its identity, polarity and threshold (#350). CLASSIFIER_MODEL picks one.
# Bumping a revision is a model change: re-run the L2 benchmark and update
# the expectations in tests/test_l2_integration.py.
COPY scripts/export_l2_model.py /usr/local/bin/export_l2_model.py

# Default: Horizon-Labs/prompt-injection-guard-small (Apache-2.0, ungated).
ARG HORIZON_REVISION=3215a27edd62c5ba0bd786c57a9d243b2158e70e
RUN python /usr/local/bin/export_l2_model.py \
      --repo Horizon-Labs/prompt-injection-guard-small \
      --revision "${HORIZON_REVISION}" \
      --out /models/prompt-injection-guard-small \
      --id prompt-injection-guard-small \
      --license Apache-2.0 \
      --threshold 0.7 \
      --malicious-labels INJECTION

# Llama Prompt Guard 2 86M. Gated: requires HF_TOKEN. Its config.json names
# no labels, so the manifest names the malicious output by index.
ARG HF_TOKEN
ARG PG2_REVISION=a8ded8e697ce7c355e395a0df51f94adb4a2fd27
RUN HF_TOKEN="${HF_TOKEN}" python /usr/local/bin/export_l2_model.py \
      --repo meta-llama/Llama-Prompt-Guard-2-86M \
      --revision "${PG2_REVISION}" \
      --out /models/prompt-guard-2-86m \
      --id prompt-guard-2-86m \
      --license "Llama 4 Community License Agreement" \
      --threshold 0.5 \
      --malicious-indices 1

# ============================================================
# Stage 2: pip install (builder variant — has shell for RUN)
# Hummingbird default is distroless (no /bin/sh), so pip install
# must happen in a builder stage. Installed packages are copied
# into the final distroless image.
# ============================================================
FROM quay.io/hummingbird/python:latest-builder AS pip-builder
USER 0

WORKDIR /app
COPY pyproject.toml README.md uv.lock ./
COPY src/ ./src/

# Dependencies come from uv.lock, not from a fresh resolve (issue #79). Every
# dependency in pyproject.toml is floor-pinned with no upper bound, so a plain
# `pip install .` here built the production image against whatever had been
# released that morning — the artifact that actually runs was the least pinned
# thing we owned, and it was resolved separately from the set CI tested.
#
# The `matrix` and `bridge` extras must appear in BOTH places below or the
# dependency is half-installed: `--extra matrix --extra bridge` puts vodozemac
# and matrix-nio in the exported, hash-pinned requirements, and
# `.[matrix,bridge]` on the final --no-deps install is what records
# it against the project. Exporting without installing gives you a verified
# wheel nobody imports; installing without exporting gives you an unpinned one.
#
# `uv export` emits hashes, so this is also a verified install. The project
# itself goes in second with --no-deps so pip cannot re-resolve around the lock.
#
# petit-log-crunchtools used to be held out of this export and installed from
# a hashed source archive, because it resolved from a git tag and pip refuses
# a VCS requirement under hash checking. It reached PyPI as of 4.1.1 (issue
# #96), so it is now an ordinary locked, hash-verified dependency like every
# other one and needs no special case here.
RUN pip install --no-cache-dir uv \
 && uv export --frozen --no-dev --extra matrix --extra bridge --no-emit-project \
      --format requirements-txt -o /tmp/requirements.txt \
 && pip install --no-cache-dir --prefix=/usr -r /tmp/requirements.txt \
 && pip install --no-cache-dir --prefix=/usr --no-deps '.[matrix,bridge]'

# onnxruntime >= 1.29 reads /etc/machine-id during module init. When that file
# is absent it falls back to popen("blkid")/popen("hostname"), and popen returns
# NULL in a distroless image with no /bin/sh. The return value is not checked,
# so the following fclose(NULL) segfaults the interpreter on `import onnxruntime`.
# Providing the file short-circuits the fallback before popen is ever reached.
RUN tr -d - < /proc/sys/kernel/random/uuid > /etc/machine-id.seed

# ============================================================
# Stage 3: Runtime image (distroless — no shell, no dnf)
# ============================================================
FROM quay.io/hummingbird/python:latest

# Supplied by CI from the release metadata. It was a hardcoded "0.4.0" that
# went unchanged through every release up to 0.7.0, so the image labelled
# itself with a version it had not been for a long time. A default is kept so
# a local build still works; CI always overrides it.
ARG VERSION=0.0.0-dev

LABEL name="mcp-trentina-crunchtools" \
      version="${VERSION}" \
      summary="MCP gateway for AI agents: injection defense, token savings, policy and auth" \
      description="MCP gateway between AI agents and their tools, the web and Matrix: three-layer prompt-injection defense, smaller tool lists and responses, gateway-enforced parameter and response guards, OAuth/DCR, and per-agent profiles" \
      maintainer="crunchtools.com" \
      url="https://github.com/crunchtools/mcp-trentina" \
      io.k8s.display-name="MCP Trentina CrunchTools" \
      io.openshift.tags="mcp,mcp-gateway,security,prompt-injection,oauth,token-efficiency" \
      org.opencontainers.image.source="https://github.com/crunchtools/mcp-trentina" \
      org.opencontainers.image.description="MCP gateway for AI agents: injection defense, token savings, policy and auth" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      com.meta.llama.built-with="Built with Llama" \
      com.meta.llama.model="Llama-Prompt-Guard-2-86M" \
      com.meta.llama.license="Llama 4 Community License Agreement" \
      com.crunchtools.l2.default="Horizon-Labs/prompt-injection-guard-small (Apache-2.0)"

WORKDIR /app

# Copy libstdc++ from model-builder — required by onnxruntime/numpy C extensions
COPY --from=model-builder /usr/lib64/libstdc++.so.6* /usr/lib64/

# Copy ONNX model files from model-builder (no PyTorch in final image).
# Both L2 models ship; CLASSIFIER_MODEL selects one (#350).
COPY --from=model-builder /models/prompt-injection-guard-small/ /models/prompt-injection-guard-small/
COPY --from=model-builder /models/prompt-guard-2-86m/ /models/prompt-guard-2-86m/

# Copy installed Python packages from pip-builder (pure Python + native C extensions)
COPY --from=pip-builder /usr/lib/python3.14/site-packages/ /usr/lib/python3.14/site-packages/
COPY --from=pip-builder /usr/lib64/python3.14/site-packages/ /usr/lib64/python3.14/site-packages/

# Keeps onnxruntime off its shell-based fallback path — see pip-builder stage
COPY --from=pip-builder /etc/machine-id.seed /etc/machine-id

ENV QUARANTINE_DB=/data/quarantine.db
ENV CLASSIFIER_MODEL=prompt-injection-guard-small
# The OAuth proxy's DCR registrations and token metadata live under
# FASTMCP_HOME. Baked in so a deploy that forgets the operator env-file does
# not silently fall back to ephemeral storage and drop every web client's
# registration on the next restart. See docs/authentication.md.
ENV FASTMCP_HOME=/data/fastmcp

# Left on, onnxruntime's init reads /etc/machine-id and /proc/cpuinfo, reads
# /etc/os-release four times, writes /tmp/mat-debug-1.log and creates a session
# file at /tmp/.ses. Not appropriate in an image built to handle untrusted
# content. Disabling leaves the /sys/class/drm and /sys/class/accel probes it
# needs to pick an execution provider. The machine-id read that segfaults a
# shell-less image lives on this same path, so both fixes are kept: either one
# alone prevents the crash.
ENV ORT_DISABLE_TELEMETRY=1

# `python -m` puts the working directory first on sys.path, and onnxruntime
# and transformers are imported lazily, so a writable /app turned any file
# write into code execution at the next import (#268). PYTHONSAFEPATH drops
# that entry. No bytecode is written either: with --read-only it could not be,
# and without it a .pyc beside the package is one more file to plant.
ENV PYTHONSAFEPATH=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 8019
ENTRYPOINT ["python", "-m", "mcp_trentina_crunchtools"]
