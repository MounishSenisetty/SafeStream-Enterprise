# SafeStream Enterprise Kafka connector.
#   docker build -t safestream-enterprise:0.3.0 .
#
# Two stages: dependencies are installed with pip in a full Debian image, then
# copied into a distroless runtime that has no shell, no package manager and no
# pip, so a compromised process has almost nothing to work with.
# Both stages are Debian 12 + CPython 3.11, so the compiled wheels
# (confluent-kafka/librdkafka, orjson, pydantic-core) are ABI-compatible.
# Both base images are pinned by multi-arch index digest (amd64 + arm64), so a
# rebuild of the same commit gets the same bases; Dependabot proposes updates.

FROM python:3.11-slim-bookworm@sha256:94a8fee35252d06ab75856f15f12c7bae67b10e8a6da93c7fded82b2610926cd AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
# --only-binary: refuse source builds, so the runtime gets exactly the
# manylinux wheels resolved here and no compiler toolchain is ever needed.
RUN pip install --only-binary=:all: --target /install .

FROM gcr.io/distroless/python3-debian12:nonroot@sha256:7d1042ce588ab97019fe95c24ffca7bc5a82ccdac572511d5e09bda4435c89c5
COPY --from=build /install /app/site-packages
ENV PYTHONPATH=/app/site-packages \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
# Distroless "nonroot" user (uid/gid 65532). Numeric, so Kubernetes'
# runAsNonRoot check can verify it without reading /etc/passwd.
USER 65532:65532
ENTRYPOINT ["/usr/bin/python3", "-m", "safestream_enterprise.connectors.kafka"]
