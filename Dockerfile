# SafeStream Enterprise Kafka connector.
#   docker build -t safestream-enterprise:0.3.0 .
#
# Two stages: dependencies are installed with pip in a full Debian image, then
# copied into a distroless runtime that has no shell, no package manager and no
# pip, so a compromised process has almost nothing to work with.
# Both stages are Debian 13 + CPython 3.13, so the compiled wheels
# (confluent-kafka/librdkafka, orjson, pydantic-core) are ABI-compatible.
# Both base images are pinned by multi-arch index digest (amd64 + arm64), so a
# rebuild of the same commit gets the same bases; Dependabot proposes updates.

FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
# Dependencies first, from the lock file: exact versions, every wheel checked
# against its recorded hash, so a rebuild of the same commit installs the same
# bytes. --only-binary: refuse source builds, so no compiler toolchain is needed.
COPY requirements.txt ./
RUN pip install --only-binary=:all: --require-hashes --target /install -r requirements.txt
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
# --no-deps: everything this package needs was installed, verified, above.
RUN pip install --no-deps --target /install .

FROM gcr.io/distroless/python3-debian13:nonroot@sha256:c3ed2b61f3c4e410685565ceb3c818197b552832521b39d53eca5d2d9d0dc1e1
COPY --from=build /install /app/site-packages
ENV PYTHONPATH=/app/site-packages \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
# Distroless "nonroot" user (uid/gid 65532). Numeric, so Kubernetes'
# runAsNonRoot check can verify it without reading /etc/passwd.
USER 65532:65532
ENTRYPOINT ["/usr/bin/python3", "-m", "safestream_enterprise.connectors.kafka"]
