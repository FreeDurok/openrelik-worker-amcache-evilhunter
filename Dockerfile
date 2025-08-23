# Base image
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
 && update-ca-certificates && rm -rf /var/lib/apt/lists/*

ARG OPENRELIK_PYDEBUG
ENV OPENRELIK_PYDEBUG=${OPENRELIK_PYDEBUG:-0}
ARG OPENRELIK_PYDEBUG_PORT
ENV OPENRELIK_PYDEBUG_PORT=${OPENRELIK_PYDEBUG_PORT:-5678}

ENV AMCACHE_EVILHUNTER_VERSION=0.0.3
WORKDIR /openrelik

# uv runtime
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Pre-sync (project deps only)
COPY uv.lock pyproject.toml .
RUN uv sync --locked --no-install-project --no-dev

# Vendor EVH script (fallback name)
RUN set -e; \
    mkdir -p /openrelik/vendor/amcache-evilhunter; \
    U1="https://raw.githubusercontent.com/cristianzsh/amcache-evilhunter/${AMCACHE_EVILHUNTER_VERSION}/amcache-evilhunter.py"; \
    U2="https://raw.githubusercontent.com/cristianzsh/amcache-evilhunter/${AMCACHE_EVILHUNTER_VERSION}/amcache_evilhunter.py"; \
    curl -fsSL "$U1" -o /openrelik/vendor/amcache-evilhunter/amcache-evilhunter.py \
 || curl -fsSL "$U2" -o /openrelik/vendor/amcache-evilhunter/amcache-evilhunter.py

# Copy app and final sync
COPY . ./
RUN uv sync --locked --no-dev

# >>> Ensure EVH runtime deps AFTER final sync (so they persist)
RUN uv pip install -q requests rich python-registry

# Wrapper: use venv Python
RUN printf '%s\n' '#!/usr/bin/env sh' \
    'exec /openrelik/.venv/bin/python -u /openrelik/vendor/amcache-evilhunter/amcache-evilhunter.py "$@"' \
    > /usr/local/bin/amcache-evilhunter && chmod +x /usr/local/bin/amcache-evilhunter

ENV PATH="/openrelik/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    PYTHONUNBUFFERED=1 \
    AMCACHE_EVILHUNTER_SCRIPT=/openrelik/vendor/amcache-evilhunter/amcache-evilhunter.py

CMD ["celery", "--app=src.tasks", "worker", "--task-events", "--concurrency=1", "--loglevel=DEBUG"]
