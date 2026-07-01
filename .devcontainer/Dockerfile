# Python 3.12 on Debian slim — matches the interpreter pinned for the suite
FROM python:3.12-slim-bookworm

# WeasyPrint's native libraries (the same deps as Phase 3), baked into the
# image because they rarely change — Docker caches this whole layer.
RUN apt-get update && apt-get install -y --no-install-recommends \
      libpango-1.0-0 \
      libpangoft2-1.0-0 \
      libharfbuzz0b \
      libjpeg-dev \
      libopenjp2-7-dev \
      libffi-dev \
      git \
    && rm -rf /var/lib/apt/lists/*

# Bring uv in from Astral's official image (multi-stage copy — the clean way)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
