# SPDX-License-Identifier: Apache-2.0
# ZeroTrace — Multi-stage container build

# ── Stage 1: Builder ────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: Runtime ────────────────────────────────────
FROM python:3.11-slim

LABEL org.opencontainers.image.title="ZeroTrace IoT Honeypot"
LABEL org.opencontainers.image.description="Zero Trust eBPF Forensics for IoT Honeypots"
LABEL org.opencontainers.image.source="https://github.com/YOUR_ORG/zerotrace"
LABEL org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /install /usr/local

WORKDIR /app

COPY src/honeypot/ /app/honeypot/
COPY src/correlator/ /app/correlator/
COPY src/spire/conf/ /app/spire/conf/
COPY src/tetragon/policies/ /app/tetragon/policies/
COPY src/scripts/ /app/scripts/

RUN useradd --create-home --shell /bin/bash zerotrace
USER zerotrace

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "import requests; requests.get('http://localhost:80', timeout=3)" || exit 1

EXPOSE 80 443 1883

CMD ["python3", "-m", "http.server", "8080"]
