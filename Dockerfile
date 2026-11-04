# Kafka redaction connector image. Build: docker build -t safestream-enterprise .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[kafka]" && rm -rf /app/src

# Never run a service that sees every record as root.
USER 65532:65532
ENTRYPOINT ["safestream-kafka"]
