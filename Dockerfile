FROM python:3.14-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONPATH=/app

RUN groupadd --system --gid 10001 evergarden \
    && useradd --system --uid 10001 --gid 10001 --create-home --home-dir /home/evergarden evergarden

WORKDIR /app
COPY --chown=10001:10001 . /app
RUN python -m pip install uv==0.11.7 \
    && uv sync --frozen --no-dev

ENV PATH="/app/.venv/bin:$PATH"
ARG EVERGARDEN_SERVICE_VERSION=unversioned
ENV EVERGARDEN_SERVICE_VERSION=$EVERGARDEN_SERVICE_VERSION

USER 10001:10001
EXPOSE 8000 8010 8020
CMD ["python", "-m", "apps.mcp.main"]
