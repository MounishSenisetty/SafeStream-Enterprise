# SafeStream Enterprise Kafka connector.
#   docker build -t safestream-enterprise:0.1.0 .
#
# Two stages: dependencies are installed with pip in a full Debian image, then
# copied into a distroless runtime that has no shell, no package manager and no
# pip, so a compromised process has almost nothing to work with.
# Both stages are Debian 12 + CPython 3.11, so the compiled wheels
# (confluent-kafka/librdkafka, orjson, pydantic-core) are ABI-compatible.
# For production, pin both images by digest (@sha256:...) instead of tag.

FROM python:3.11-slim-bookworm AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
# --only-binary: refuse source builds, so the runtime gets exactly the
# manylinux wheels resolved here and no compiler toolchain is ever needed.
RUN pip install --only-binary=:all: --target /install .

FROM gcr.io/distroless/python3-debian12:nonroot
COPY --from=build /install /app/site-packages
ENV PYTHONPATH=/app/site-packages \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
# Distroless "nonroot" user (uid/gid 65532). Numeric, so Kubernetes'
# runAsNonRoot check can verify it without reading /etc/passwd.
USER 65532:65532
ENTRYPOINT ["/usr/bin/python3", "-m", "safestream_enterprise.connectors.kafka"]
