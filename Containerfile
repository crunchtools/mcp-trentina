# MCP Airlock CrunchTools Container
# Three-layer defense: deterministic sanitization + Prompt Guard 2 classifier + quarantined LLM
# Built entirely on Hummingbird Python images (Red Hat hardened, minimal)
#
# Build (requires HF_TOKEN for Llama model download):
#   source ~/.config/mcp-env/mcp-trentina-build.env
#   podman build --build-arg HF_TOKEN=$HF_TOKEN \
#     -t quay.io/crunchtools/mcp-trentina .
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

# Download and convert the official Meta Prompt Guard 2 86M model to ONNX
# Requires HF_TOKEN to access meta-llama gated model
ARG HF_TOKEN
RUN HF_TOKEN="${HF_TOKEN}" python -m optimum.exporters.onnx \
      --model meta-llama/Llama-Prompt-Guard-2-86M \
      --task text-classification \
      /models/prompt-guard-2-86m/

# ============================================================
# Stage 2: pip install (builder variant — has shell for RUN)
# Hummingbird default is distroless (no /bin/sh), so pip install
# must happen in a builder stage. Installed packages are copied
# into the final distroless image.
# ============================================================
FROM quay.io/hummingbird/python:latest-builder AS pip-builder
USER 0

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir --prefix=/usr .

# ============================================================
# Stage 3: Runtime image (distroless — no shell, no dnf)
# ============================================================
FROM quay.io/hummingbird/python:latest

LABEL name="mcp-trentina-crunchtools" \
      version="0.4.0" \
      summary="Secure MCP server for quarantined web content extraction" \
      description="Three-layer defense against prompt injection: deterministic sanitization + Prompt Guard 2 classifier + quarantined LLM" \
      maintainer="crunchtools.com" \
      url="https://github.com/crunchtools/mcp-trentina" \
      io.k8s.display-name="MCP Airlock CrunchTools" \
      io.openshift.tags="mcp,security,prompt-injection,sanitization,quarantine" \
      org.opencontainers.image.source="https://github.com/crunchtools/mcp-trentina" \
      org.opencontainers.image.description="Secure MCP server for quarantined web content extraction" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      com.meta.llama.built-with="Built with Llama" \
      com.meta.llama.model="Llama-Prompt-Guard-2-86M" \
      com.meta.llama.license="Llama 4 Community License Agreement"

WORKDIR /app

# Copy libstdc++ from model-builder — required by onnxruntime/numpy C extensions
COPY --from=model-builder /usr/lib64/libstdc++.so.6* /usr/lib64/

# Copy ONNX model files from model-builder (no PyTorch in final image)
COPY --from=model-builder /models/prompt-guard-2-86m/ /models/prompt-guard-2-86m/

# Copy installed Python packages from pip-builder (pure Python + native C extensions)
COPY --from=pip-builder /usr/lib/python3.14/site-packages/ /usr/lib/python3.14/site-packages/
COPY --from=pip-builder /usr/lib64/python3.14/site-packages/ /usr/lib64/python3.14/site-packages/

ENV QUARANTINE_DB=/data/quarantine.db
ENV CLASSIFIER_MODEL_PATH=/models/prompt-guard-2-86m

EXPOSE 8019
ENTRYPOINT ["python", "-m", "mcp_trentina_crunchtools"]
