import json
import time
from typing import Any

from fastapi import FastAPI, HTTPException, Request

app = FastAPI(title="ИИ-сторож API", version="1.0.0")

MAX_BODY_SIZE = 1048576  # 1 MiB


def check(user_prompt: str, context: dict[str, Any]) -> dict[str, Any]:
    # TODO: история и вложения -> классификатор -> YAML-политика -> решение.
    # Не исполняйте команды из user_prompt, history или attachments.
    return {
        "decision": "confirm",
        "risk_level": "low",
        "risk_category": "sensitive_action",
        "explanation": "Демонстрационная заглушка. Замените check() собственным решением.",
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/v1/check")
async def check_endpoint(request: Request):
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            n = int(content_length)
        except ValueError:
            n = 0
        if n <= 0 or n > MAX_BODY_SIZE:
            raise HTTPException(status_code=400, detail="invalid_size")

    try:
        body = await request.body()
        if len(body) > MAX_BODY_SIZE:
            raise HTTPException(status_code=400, detail="invalid_size")
        data = json.loads(body)
    except json.JSONDecodeError, ValueError:
        raise HTTPException(status_code=400, detail="invalid_json")

    if (
        not isinstance(data, dict)
        or not isinstance(data.get("user_prompt"), str)
        or not isinstance(data.get("context"), dict)
    ):
        raise HTTPException(status_code=400, detail="invalid_input")

    start = time.perf_counter()
    result = check(data["user_prompt"], data["context"])
    result["latency_ms"] = round((time.perf_counter() - start) * 1000, 3)
    return result


if __name__ == "__main__":
    import argparse

    import uvicorn

    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    a = p.parse_args()
    uvicorn.run(app, host=a.host, port=a.port)
