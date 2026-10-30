# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv/app

# 依赖层单独缓存
COPY packages/contracts/pyproject.toml /srv/app/packages/contracts/pyproject.toml
COPY apps/api/pyproject.toml /srv/app/apps/api/pyproject.toml
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip && \
    pip install -e /srv/app/packages/contracts && \
    pip install -e /srv/app/apps/api

# 源码层
COPY packages/contracts/src /srv/app/packages/contracts/src
COPY apps/api/src /srv/app/apps/api/src
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-deps -e /srv/app/packages/contracts && \
    pip install --no-deps -e /srv/app/apps/api

# 非 root 运行
RUN useradd --create-home --uid 10001 appuser && \
    mkdir -p /srv/app/var && chown -R appuser:appuser /srv/app
USER appuser

ENV PYTHONPATH=/srv/app/packages/contracts/src:/srv/app/apps/api/src \
    PORT=8000

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)"

CMD ["python", "-m", "uvicorn", "rg_api.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
