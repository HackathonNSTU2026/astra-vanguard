FROM ghcr.io/astral-sh/uv:python3.14-alpine AS runtime

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

FROM runtime AS training
COPY backend/scripts/train.py ./scripts/train.py
COPY backend/dataset/dev.jsonl backend/dataset/generalization_train.jsonl ./dataset/
RUN OPENBLAS_NUM_THREADS=1 python scripts/train.py

FROM runtime
ENV BUNDLED_MODEL_DIR=/opt/astra/classifier
COPY --from=training /app/models/classifier /opt/astra/classifier

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

ENTRYPOINT ["python", "-m", "uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
