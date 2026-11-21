FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    MAX1M_DATA_DIR=/data

RUN groupadd -g 10001 max1m && \
    useradd -u 10001 -g max1m -d /app -s /usr/sbin/nologin max1m && \
    mkdir -p /app /data && \
    chown -R max1m:max1m /app /data && \
    chmod 0700 /data

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential libffi-dev && \
    pip install --upgrade pip && \
    pip install -r /app/requirements.txt && \
    apt-get purge -y --auto-remove build-essential libffi-dev && \
    rm -rf /var/lib/apt/lists/*

COPY app /app/app
COPY create_invite.py run_server.py alembic.ini /app/
COPY migrations /app/migrations
RUN chown -R max1m:max1m /app

USER max1m
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/', timeout=3)" || exit 1

# --no-access-log prevents writing client IP addresses and request paths to container logs
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
