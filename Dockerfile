FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TRAILWEAVER_DATABASE_PATH=/data/incidents.sqlite3 \
    TRAILWEAVER_API_HOST=0.0.0.0 \
    TRAILWEAVER_API_PORT=8000

WORKDIR /app

COPY requirements-runtime.lock /tmp/requirements-runtime.lock
RUN python -m pip install --no-cache-dir --requirement /tmp/requirements-runtime.lock \
    && rm /tmp/requirements-runtime.lock \
    && groupadd --system --gid 10001 trailweaver \
    && useradd --system --uid 10001 --gid trailweaver --home-dir /home/trailweaver trailweaver \
    && mkdir -p /data \
    && chown trailweaver:trailweaver /data

COPY --chown=trailweaver:trailweaver src/ /app/src/

ENV PYTHONPATH=/app/src
USER 10001:10001

EXPOSE 8000
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"]

ENTRYPOINT ["python", "-m", "trailweaver.cli"]
CMD ["serve"]
