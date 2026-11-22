from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from src.adapter import DemoAdapter
from src.config.settings import load_settings
from src.guard import Guard
from src.session import SessionManager

settings = load_settings()
model_dir = Path(os.environ.get('MODEL_DIR', 'models/classifier'))
bundled_dir = os.environ.get('BUNDLED_MODEL_DIR')
if bundled_dir and not (model_dir / 'classifier.joblib').is_file():
    model_dir = Path(bundled_dir)
guard = Guard(settings, model_dir=model_dir)
if bundled_dir and guard.classifier.model is None:
    raise RuntimeError(f'Не удалось загрузить классификатор из {model_dir}')
_policy_path = settings.policy_path
_adapter = DemoAdapter(settings.adapter_path)
_sessions = SessionManager(settings.sessions_path)

app = FastAPI(title='Астра Авангард API', version='1.0.0', docs_url=None, redoc_url=None)

MAX_BODY_SIZE = 1048576  # 1 MiB


def _parse_json_body(body: bytes) -> dict[str, Any]:
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        raise HTTPException(status_code=400, detail='invalid_json')
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail='invalid_input')
    return data


@app.get('/health')
def health():
    return {
        'status': 'ok',
        'policy_version': guard.policy.version,
        'model_loaded': guard.classifier.model is not None,
    }


@app.get('/admin/policy')
def admin_policy():
    try:
        return _policy_path.read_text(encoding='utf-8')
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='policy_not_found')


@app.post('/admin/policy/reload')
def admin_reload_policy():
    guard.reload_policy()
    return {'status': 'reloaded', 'policy_version': guard.policy.version}


@app.get('/admin/journal')
def admin_journal(limit: int = 50):
    entries = guard.journal.entries(limit=limit)
    return [e.__dict__ for e in entries]


@app.post('/v1/check')
async def check_endpoint(request: Request):
    content_length = request.headers.get('content-length')
    if content_length is not None:
        try:
            n = int(content_length)
        except ValueError:
            n = 0
        if n <= 0 or n > MAX_BODY_SIZE:
            raise HTTPException(status_code=400, detail='invalid_size')

    body = await request.body()
    if len(body) > MAX_BODY_SIZE:
        raise HTTPException(status_code=400, detail='invalid_size')

    data = _parse_json_body(body)

    if not isinstance(data.get('user_prompt'), str) or not isinstance(
        data.get('context'), dict
    ):
        raise HTTPException(status_code=400, detail='invalid_input')

    response: Guard.CheckResponse | None = None
    try:
        response = guard.check(data['user_prompt'], data['context'])
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f'internal_error: {exc}')

    # Если confirm — создаём pending в адаптере
    pending_id = None
    if response.decision == 'confirm':
        ctx = data['context']
        pending_id = _adapter.submit_for_confirm(
            user_id=ctx.get('user_id', 'unknown'),
            user_prompt=data['user_prompt'],
            context=ctx,
            decision='confirm',
        )

    return JSONResponse(
        {
            'decision': response.decision,
            'risk_level': response.risk_level,
            'risk_category': response.risk_category,
            'explanation': response.explanation,
            'latency_ms': response.latency_ms,
            'pending_id': pending_id,
        }
    )


@app.post('/v1/adapter/confirm')
def adapter_confirm(payload: dict[str, Any]):
    pending_id = payload.get('pending_id')
    user_id = payload.get('user_id')
    if not pending_id or not user_id:
        raise HTTPException(status_code=400, detail='missing_fields')
    ok = _adapter.confirm(
        pending_id,
        user_id,
        lambda prompt, context: (
            guard.check(prompt, context).decision in {'allow', 'confirm'}
        ),
    )
    if not ok:
        raise HTTPException(status_code=400, detail='confirm_failed')
    return {'ok': True}


@app.post('/v1/adapter/cancel')
def adapter_cancel(payload: dict[str, Any]):
    pending_id = payload.get('pending_id')
    user_id = payload.get('user_id')
    if not pending_id or not user_id:
        raise HTTPException(status_code=400, detail='missing_fields')
    ok = _adapter.cancel(pending_id, user_id)
    if not ok:
        raise HTTPException(status_code=400, detail='cancel_failed')
    return {'ok': True}


@app.get('/v1/adapter/received')
def adapter_received():
    return [r.__dict__ for r in _adapter.received()]


@app.get('/v1/adapter/pending/{user_id}')
def adapter_pending(user_id: str):
    return [p.__dict__ for p in _adapter.list_pending(user_id)]


# ---------- Session endpoints (бонус) ----------


@app.post('/v1/session/create')
def session_create(payload: dict[str, Any]):
    user_id = payload.get('user_id')
    if not user_id:
        raise HTTPException(status_code=400, detail='missing_user_id')
    sid = _sessions.create(user_id)
    return {'session_id': sid}


@app.get('/v1/session/{session_id}/history')
def session_history(session_id: str):
    return {'history': _sessions.history(session_id)}


@app.post('/v1/session/{session_id}/message')
def session_message(session_id: str, payload: dict[str, Any]):
    role = payload.get('role')
    content = payload.get('content')
    if not role or content is None:
        raise HTTPException(status_code=400, detail='missing_fields')
    ok = _sessions.add_message(session_id, role, content)
    if not ok:
        raise HTTPException(status_code=404, detail='session_not_found')
    return {'ok': True}


@app.delete('/v1/session/{session_id}')
def session_delete(session_id: str, payload: dict[str, Any]):
    user_id = payload.get('user_id')
    if not user_id:
        raise HTTPException(status_code=400, detail='missing_user_id')
    ok = _sessions.delete(session_id, user_id)
    if not ok:
        raise HTTPException(
            status_code=404, detail='session_not_found_or_access_denied'
        )
    return {'ok': True}


if __name__ == '__main__':
    import argparse

    import uvicorn

    p = argparse.ArgumentParser()
    p.add_argument('--host', default=settings.host)
    p.add_argument('--port', type=int, default=settings.port)
    a = p.parse_args()
    uvicorn.run(app, host=a.host, port=a.port)
