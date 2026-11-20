from __future__ import annotations

import json
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from src.adapter import DemoAdapter
from src.config.settings import load_settings
from src.guard import Guard
from src.journal import Journal
from src.session import SessionManager

settings = load_settings()
guard = Guard(settings, model_dir='models/classifier')
_policy_path = settings.policy_path
_journal = Journal(settings.journal_path, policy_version=guard.policy.version)
_adapter = DemoAdapter(settings.adapter_path)
_sessions = SessionManager(settings.sessions_path)

app = FastAPI(title='ИИ-сторож API', version='1.0.0')

MAX_BODY_SIZE = 1048576  # 1 MiB

DEMO_HTML = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ИИ-сторож — демо</title>
<style>
* { box-sizing: border-box; }
body { font-family: system-ui, -apple-system, sans-serif; margin: 0; padding: 20px; background: #f5f5f7; }
.max { max-width: 900px; margin: 0 auto; }
h1 { font-size: 1.25rem; margin-bottom: 1rem; color: #1a1a1a; }
.card { background: #fff; border-radius: 12px; padding: 20px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
.label { font-size: 0.85rem; color: #666; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; font-weight: 600; }
textarea, select, input { width: 100%; padding: 10px; border: 1px solid #d4d4d4; border-radius: 6px; font-size: 0.95rem; font-family: inherit; }
textarea { min-height: 120px; resize: vertical; font-family: ui-monospace, SFMono-Regular, monospace; }
.row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.btn { background: #0070f3; color: #fff; border: none; padding: 10px 20px; border-radius: 6px; font-size: 0.95rem; cursor: pointer; font-weight: 500; }
.btn:hover { background: #0060df; }
.btn.secondary { background: #e5e5ea; color: #1a1a1a; }
.btn.secondary:hover { background: #d4d4d8; }
.btn.danger { background: #ff3b30; }
.btn.success { background: #34c759; }
.result { margin-top: 16px; padding: 16px; border-radius: 8px; display: none; }
.result.allow { background: #e6f4ea; border: 1px solid #34c759; color: #1e6b33; }
.result.confirm { background: #fffbe6; border: 1px solid #ffd60a; color: #8a6d00; }
.result.block { background: #fdecea; border: 1px solid #ff3b30; color: #c42313; }
.decision-badge { display: inline-block; padding: 4px 10px; border-radius: 12px; font-size: 0.8rem; font-weight: 700; text-transform: uppercase; }
.allow-badge { background: #34c759; color: #fff; }
.confirm-badge { background: #ffd60a; color: #6d5000; }
.block-badge { background: #ff3b30; color: #fff; }
.confirm-section { margin-top: 16px; display: none; }
.adapters { margin-top: 16px; padding-top: 16px; border-top: 1px solid #e5e5ea; }
.history-item { padding: 8px 0; border-bottom: 1px solid #eee; font-size: 0.9rem; }
.history-item:last-child { border-bottom: none; }
.tip { font-size: 0.85rem; color: #666; margin-top: 8px; }
</style>
</head>
<body>
<div class="max">
<h1>🛡️ ИИ-сторож — демонстрационный интерфейс</h1>

<div class="card">
<div class="label">Запрос (user_prompt)</div>
<textarea id="prompt" placeholder="Например: Перезапусти payments-api в production."></textarea>

<div class="row">
<div>
<div class="label">Роль пользователя</div>
<select id="role">
<option value="developer">developer</option>
<option value="sre">sre</option>
<option value="admin">admin</option>
</select>
</div>
<div>
<div class="label">ID пользователя</div>
<input id="userId" value="u-demo" />
</div>
</div>

<div class="label">История диалога (JSON массив)</div>
<textarea id="history" placeholder='[{"role":"user","content":"..."}]'></textarea>

<div class="label">Вложения (JSON массив)</div>
<textarea id="attachments" placeholder='[{"type":"document","name":"README.md","content":"..."}]'></textarea>

<button class="btn" onclick="check()">Проверить запрос</button>
<button class="btn secondary" onclick="loadExamples()">Загрузить примеры</button>
</div>

<div id="result" class="result"></div>

<div id="confirmSection" class="confirm-section">
<div class="label">Требуется подтверждение</div>
<p id="confirmText"></p>
<button class="btn success" onclick="confirmAction()">Подтвердить и отправить агенту</button>
<button class="btn danger" onclick="cancelAction()">Отклонить</button>
</div>

<div id="adapterSection" class="adapters">
<div class="label">Полученные запросы адаптера</div>
<div id="adapterList"></div>
</div>
</div>

<script>
let pendingId = null;

async function check() {
  const res = await fetch('/v1/check', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      user_prompt: document.getElementById('prompt').value,
      context: {
        target_agent: 'it_ops_agent',
        user_role: document.getElementById('role').value,
        user_id: document.getElementById('userId').value,
        user_name: 'Demo User',
        system_prompt: 'Ты — DevOps-ассистент инженерной команды.',
        history: tryParse(document.getElementById('history').value, []),
        attachments: tryParse(document.getElementById('attachments').value, []),
      }
    })
  });
  const data = await res.json();
  showResult(data);
}

function showResult(data) {
  const result = document.getElementById('result');
  const confirmSection = document.getElementById('confirmSection');
  result.style.display = 'block';
  result.className = 'result ' + data.decision;

  let badgeClass = data.decision === 'allow' ? 'allow-badge' : data.decision === 'confirm' ? 'confirm-badge' : 'block-badge';

  result.innerHTML =
    '<span class="decision-badge ' + badgeClass + '">' + data.decision + '</span> ' +
    '<strong>Риск:</strong> ' + data.risk_level + ' / ' + data.risk_category + '<br>' +
    '<strong>Задержка:</strong> ' + data.latency_ms + ' мс<br>' +
    '<strong>Объяснение:</strong> ' + data.explanation;

  if (data.decision === 'confirm') {
    pendingId = null;
    confirmSection.style.display = 'block';
    document.getElementById('confirmText').textContent = data.explanation;
  } else {
    confirmSection.style.display = 'none';
    if (data.decision === 'allow') {
      loadAdapter();
    }
  }
}

async function confirmAction() {
  if (!pendingId) {
    // Для демо создаем pending через check с confirm — здесь просто имитируем
    alert('Сначала получите решение confirm через проверку.');
    return;
  }
  const res = await fetch('/v1/adapter/confirm', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ pending_id: pendingId, user_id: document.getElementById('userId').value })
  });
  const data = await res.json();
  if (data.ok) {
    alert('Запрос подтверждён и отправлен агенту.');
    document.getElementById('confirmSection').style.display = 'none';
    loadAdapter();
  } else {
    alert('Ошибка подтверждения: ' + data.detail);
  }
}

function cancelAction() {
  document.getElementById('confirmSection').style.display = 'none';
  pendingId = null;
}

async function loadAdapter() {
  const res = await fetch('/v1/adapter/received');
  const data = await res.json();
  const list = document.getElementById('adapterList');
  list.innerHTML = data.map(r =>
    '<div class="history-item"><strong>' + r.user_id + '</strong>: ' + escapeHtml(r.user_prompt) +
    ' <em>[' + r.decision + ']</em></div>'
  ).join('');
}

function tryParse(s, def) { try { return JSON.parse(s || '[]'); } catch { return def; } }
function escapeHtml(t) { return t.replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}[m])); }
function loadExamples() {
  document.getElementById('prompt').value = 'Перезапусти payments-api в production.';
  document.getElementById('role').value = 'developer';
}
</script>
</body>
</html>"""

ADMIN_HTML = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<title>ИИ-сторож — админ</title>
<style>
body { font-family: system-ui, sans-serif; margin: 0; padding: 20px; background: #f5f5f7; }
.max { max-width: 1000px; margin: 0 auto; }
h1 { font-size: 1.25rem; margin-bottom: 1rem; }
.card { background: #fff; border-radius: 12px; padding: 20px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
.label { font-size: 0.85rem; color: #666; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; font-weight: 600; }
textarea, input, select { width: 100%; padding: 10px; border: 1px solid #d4d4d4; border-radius: 6px; font-size: 0.95rem; }
.btn { background: #0070f3; color: #fff; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-weight: 500; }
.btn:hover { background: #0060df; }
.btn.secondary { background: #e5e5ea; color: #1a1a1a; }
table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
th, td { padding: 8px; text-align: left; border-bottom: 1px solid #eee; }
th { background: #f9f9f9; font-weight: 600; }
.badge { padding: 2px 8px; border-radius: 10px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }
.allow-badge { background: #e6f4ea; color: #1e6b33; }
.confirm-badge { background: #fffbe6; color: #8a6d00; }
.block-badge { background: #fdecea; color: #c42313; }
</style>
</head>
<body>
<div class="max">
<h1>⚙️ ИИ-сторож — административный интерфейс</h1>

<div class="card">
<div class="label">Текущая политика (security_policy.yaml)</div>
<pre id="policyText"></pre>
<div style="margin-top:12px">
<button class="btn" onclick="reloadPolicy()">Перезагрузить политику</button>
<button class="btn secondary" onclick="loadPolicy()">Обновить вид</button>
</div>
</div>

<div class="card">
<div class="label">Журнал решений</div>
<table id="journalTable">
<thead><tr><th>Время</th><th>Роль</th><th>Решение</th><th>Категория</th><th>Риск</th><th>Задержка</th><th>Запрос (маска)</th></tr></thead>
<tbody></tbody>
</table>
</div>
</div>

<script>
async function loadPolicy() {
  const res = await fetch('/admin/policy');
  const text = await res.text();
  document.getElementById('policyText').textContent = text;
}
async function reloadPolicy() {
  const res = await fetch('/admin/policy/reload', { method: 'POST' });
  const data = await res.json();
  alert(data.status || 'Политика перезагружена');
  loadPolicy();
}
async function loadJournal() {
  const res = await fetch('/admin/journal?limit=50');
  const data = await res.json();
  const tbody = document.querySelector('#journalTable tbody');
  tbody.innerHTML = data.map(e =>
    '<tr><td>' + e.timestamp + '</td><td>' + e.user_role + '</td>' +
    '<td><span class="badge ' + e.decision + '-badge">' + e.decision + '</span></td>' +
    '<td>' + e.risk_category + '</td><td>' + e.risk_level + '</td>' +
    '<td>' + e.latency_ms + ' мс</td><td>' + escapeHtml(e.user_prompt_masked) + '</td></tr>'
  ).join('');
}
function escapeHtml(t) { return t.replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}[m])); }
loadPolicy();
loadJournal();
setInterval(loadJournal, 5000);
</script>
</body>
</html>"""


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
    return {'status': 'ok', 'policy_version': guard.policy.version}


@app.get('/', response_class=HTMLResponse)
def demo_ui():
    return DEMO_HTML


@app.get('/admin', response_class=HTMLResponse)
def admin_ui():
    return ADMIN_HTML


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
    entries = _journal.entries(limit=limit)
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
    ok = _adapter.confirm(pending_id, user_id)
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
