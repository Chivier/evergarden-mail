# Headless Chromium layered on the tested Evergarden image. Kept separate so the
# MCP, UI and worker images carry no browser.
# docker-compose.yaml passes BASE_IMAGE=${EVERGARDEN_IMAGE:-evergarden:local}.
ARG BASE_IMAGE=evergarden:local
FROM ${BASE_IMAGE}

USER root
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN apt-get update && apt-get install -y --no-install-recommends libatomic1 \
    && uv pip install --python /app/.venv/bin/python "playwright>=1.55,<2" \
    && /app/.venv/bin/playwright install --with-deps chromium \
    && chmod -R a+rX /ms-playwright \
    && rm -rf /var/lib/apt/lists/*

USER 10001:10001
CMD ["python", "-m", "apps.mfa_autologin.main", "run"]
