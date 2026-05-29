# Warden image — mitmproxy + OpenTelemetry SDK.
# Built inside the brig VM (`./scripts/build-warden-image.sh`) so
# Python wheels match the runtime architecture, then pinned by
# sha256 in src/warden/proxy.py:IMAGE_DIGEST.

FROM docker.io/mitmproxy/mitmproxy@sha256:39ef4ec493d10bf07c71189961c7797b24c445e640ee133efba87fea80d19268

USER root
RUN pip install --no-cache-dir \
    "opentelemetry-api==1.27.0" \
    "opentelemetry-sdk==1.27.0" \
    "opentelemetry-exporter-otlp-proto-grpc==1.27.0"
USER mitmproxy

LABEL org.brig.warden.base="mitmproxy/mitmproxy@sha256:39ef4ec493d10bf07c71189961c7797b24c445e640ee133efba87fea80d19268"
LABEL org.brig.warden.otel="1.27.0"
