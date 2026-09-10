# Honeypot Framework - API / ingestor image.
#
# One image serves both roles (they share all dependencies and the alert
# database); docker-compose.yml overrides the command for the ingestor.

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Node is needed for threatintel/advanced-threat-intel.js, which the alert
# creation path shells out to for enrichment.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY api/ ./api/
COPY analytics/ ./analytics/
COPY playbooks/ ./playbooks/
COPY monitoring/ ./monitoring/
COPY threatintel/ ./threatintel/
COPY scripts/ ./scripts/
COPY database/ ./database/
COPY config/ ./config/

# Run as a non-root user; the honeypot data volume is chowned to match.
RUN useradd --create-home --uid 10001 honeypot \
    && mkdir -p /var/lib/honeypot /var/log/honeypot \
    && chown -R honeypot:honeypot /var/lib/honeypot /var/log/honeypot /app
USER honeypot

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/health || exit 1

# gunicorn imports the module-level `app`, so the __main__ TLS block in
# alerts_service.py is skipped -- nginx terminates TLS in front instead.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--timeout", "60", \
     "--access-logfile", "-", "api.alerts_service:app"]
