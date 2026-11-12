FROM python:3.15-slim-bookworm

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
# The runtime UID is operator-selectable. Source copied from a checkout with
# umask 077 must remain readable by that UID, not just the image's build owner.
RUN chmod -R a+rX /app \
    && python -m pip install uv==0.11.7 \
    && uv sync --frozen --no-dev

ENV PATH="/app/.venv/bin:$PATH"
ARG EVERGARDEN_SERVICE_VERSION=unversioned
ENV EVERGARDEN_SERVICE_VERSION=$EVERGARDEN_SERVICE_VERSION

USER 10001:10001
EXPOSE 8000 8010 8020
CMD ["python", "-m", "apps.mcp.main"]
