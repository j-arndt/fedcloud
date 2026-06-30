# FedCloud Formal Verification Gateway
# Multi-stage build: Python translator + Lean 4 proof engine
#
# Usage:
#   docker build -t fedcloud-gateway .
#   docker run -v $(pwd)/fixtures:/data fedcloud-gateway /data/mock_aws_topology.json

FROM python:3.12-slim AS translator

WORKDIR /app
COPY translator/ ./translator/
COPY oscal/ ./oscal/
COPY fixtures/ ./fixtures/

# Install Python dependencies (stdlib only for PoC)
RUN pip install --no-cache-dir pytest

# ---------------------------------------------------------------------------

FROM elan:latest AS lean-builder

# This stage builds the Lean 4 verification engine.
# In CI, this validates that all proofs compile.
#
# Note: The official leanprover/lean4 image or elan-based setup is required.
# For PoC, the Lean compilation step is documented but runs separately
# from the Python pipeline.

WORKDIR /lean
COPY lean/ ./

# Build the verification library
# RUN lake build

# ---------------------------------------------------------------------------

FROM python:3.12-slim AS runtime

LABEL maintainer="FedCloud Team"
LABEL description="Formal Verification Gateway for Federal Cloud Authorizations"
LABEL version="0.1.0"

WORKDIR /app

COPY --from=translator /app/ ./
COPY scripts/ ./scripts/ 2>/dev/null || true

# Create output directories
RUN mkdir -p /app/output /app/state

# Default: run the full verification pipeline
ENTRYPOINT ["python3", "-m", "scripts.run_pipeline"]
CMD ["--mode", "mock", "--fixtures", "/data"]
