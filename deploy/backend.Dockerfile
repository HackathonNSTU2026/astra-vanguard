FROM ghcr.io/astral-sh/uv:python3.14-alpine

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY backend/requirements.txt ./

RUN --mount=type=cache,target=/root/.cache/uv \
    apk add --no-cache libgomp libstdc++ \
    && apk add --no-cache --virtual .build-deps build-base \
    && uv pip sync --system requirements.txt \
    && apk del .build-deps

COPY backend/src ./src
COPY backend/dataset/security_policy.yaml ./dataset/security_policy.yaml

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

ENTRYPOINT ["python", "-m", "uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
