# ИИ-сторож — архитектура и запуск

## Архитектура

Проект следует принципу разделения ответственности: каждая часть независима и отвечает за свою зону.

### Модули

| Модуль | Ответственность |
|--------|-----------------|
| `src/config/settings.py` | Конфигурация: пути к политике, журналу, сессиям, адаптеру |
| `src/policy/models.py` | Модели данных политики (AgentPolicy, RolePolicy, SecurityPolicy) |
| `src/policy/loader.py` | Загрузка/перезагрузка YAML-политики с диска |
| `src/policy/engine.py` | Детерминированная проверка прав на основе YAML (без жёсткой матрицы в коде) |
| `src/policy/environments.py` | Определение окружения (prod/nonprod) по тексту и имени ресурса |
| `src/classifier/__init__.py` | Классификатор: детерминированные правила + TF-IDF + логистическая регрессия |
| `src/decision/__init__.py` | Принятие решения allow/confirm/block на основе классификации и политики |
| `src/explain/__init__.py` | Генерация объяснений с маскированием секретов |
| `src/journal/__init__.py` | Журнал решений (JSONL) с маскированием содержимого |
| `src/guard/__init__.py` | Оркестратор конвейера проверки (основной сторож) |
| `src/adapter/__init__.py` | Демо-заглушка получателя с подтверждением действий |
| `src/session/__init__.py` | Управление изолированными сессиями диалогов (бонус) |
| `src/api/main.py` | FastAPI: POST /v1/check, демо-UI, админ-интерфейс, сессии |

### Конвейер проверки (Guard)

```
user_prompt + context
    ↓
Классификация (правила → ML-модель)
    ↓
Определение окружения (prod/nonprod)
    ↓
Проверка политики YAML (права роли, инструмент, окружение)
    ↓
Решение: allow / confirm / block
    ↓
Объяснение с маскированием секретов
    ↓
Запись в журнал
    ↓
Ответ API
```

### Принципы独立стей

- **Политика не жёстко зашита**: все права ролей читаются из `dataset/security_policy.yaml`. Жюри может изменить YAML без правки кода.
- **История и вложения анализируются как материал**, а не как новые инструкции для сторожа.
- **Подтверждение не выдаёт новых прав**: фразы «я администратор» в тексте не меняют `context.user_role`.
- **Секреты не записываются в журнал**: содержимое маскируется.
- **Никаких внешних LLM API**: инференс локально, CPU-only.

## API

### POST /v1/check

Оценивает запрос и возвращает решение.

**Запрос:**
```json
{
  "user_prompt": "Перезапусти payments-api в production.",
  "context": {
    "target_agent": "it_ops_agent",
    "user_role": "developer",
    "user_id": "u-example",
    "user_name": "Иван Иванов",
    "system_prompt": "...",
    "history": [],
    "attachments": []
  }
}
```

**Ответ:**
```json
{
  "decision": "block",
  "risk_level": "high",
  "risk_category": "tool_abuse",
  "explanation": "Роль developer не допускает restart_service в production.",
  "latency_ms": 12.5,
  "pending_id": null
}
```

### Дополнительные endpoints

| Endpoint | Метод | Описание |
|----------|-------|----------|
| `GET /health` | GET | Проверка здоровья сервиса |
| `GET /openapi.json` | GET | Схема OpenAPI |
| `GET /admin/policy` | GET | Просмотр текущей политики |
| `POST /admin/policy/reload` | POST | Перезагрузка политики с диска |
| `GET /admin/journal?limit=50` | GET | Журнал решений |
| `POST /v1/adapter/confirm` | POST | Подтвердить pending-запрос |
| `POST /v1/adapter/cancel` | POST | Отклонить pending-запрос |
| `GET /v1/adapter/received` | GET | Список полученных адаптером запросов |
| `GET /v1/adapter/pending/{user_id}` | GET | Pending-подтверждения пользователя |
| `POST /v1/session/create` | POST | Создать сессию диалога |
| `GET /v1/session/{session_id}/history` | GET | История сессии |
| `POST /v1/session/{session_id}/message` | POST | Добавить сообщение в сессию |
| `DELETE /v1/session/{session_id}` | DELETE | Удалить сессию |

## Запуск

### Установка зависимостей

```bash
uv sync
```

### Запуск сервера

```bash
uv run python -m src.api.main --host 127.0.0.1 --port 8000
```

Требуется `PYTHONPATH` с корнем проекта:

```bash
PYTHONPATH=/path/to/astra-vanguard uv run python -m src.api.main --host 0.0.0.0 --port 8000
```

### Веб-интерфейс

После запуска API запустите [Svelte-фронтенд](../frontend/README.md). При запуске через Vite форма проверки доступна на http://localhost:5173/, а политика и журнал решений — на http://localhost:5173/admin.

### Обучение модели

```bash
uv run python scripts/train.py
```

Обучает TF-IDF + логистическую регрессию на `dataset/dev.jsonl` и сохраняет модель в `models/classifier`.

### Самооценка

```bash
# Запустить сервер в одном терминале
uv run python -m src.api.main --host 127.0.0.1 --port 8000

# В другом терминале:
uv run python ./src/evaluate/evaluate.py \
  --data dataset/dev.jsonl \
  --endpoint http://127.0.0.1:8000/v1/check \
  --report report.json \
  --save-predictions predictions.jsonl
```

### Unit-тесты evaluator

```bash
uv run python -m unittest src.evaluate.test_evaluate
```

### Lint

```bash
uvx ruff check src/
uvx ruff format src/
```

## Конфигурация

| Переменная | Значение по умолчанию | Описание |
|------------|----------------------|----------|
| `POLICY_PATH` | `dataset/security_policy.yaml` | Путь к YAML-политике |
| `JOURNAL_PATH` | `data/journal.jsonl` | Путь к файлу журнала |
| `SESSIONS_PATH` | `data/sessions.json` | Путь к файлу сессий |
| `ADAPTER_PATH` | `data/adapter.json` | Путь к файлу адаптера |
| `MODEL_DIR` | `models/classifier` | Директория с обученной моделью |

Редактирование `dataset/security_policy.yaml` сразу меняет решения без переобучения и без правки кода.

## Результаты оценки (на public/dev)

- **Score**: 0.917 (64.2 / 70 автоматических баллов)
- **Eligible for prizes**: да (strict_block_recall_high_critical = 0.916 ≥ 0.85)
- **Latency p95**: ~2.9 мс (требование ≤ 3000 мс для CPU-бонуса)
- **CPU bonus candidate**: да
- **Invalid/timeouts**: 0

## Структура репозитория

```
astra-vanguard/
├── dataset/
│   ├── dev.jsonl          # 500 размеченных примеров
│   ├── dev.csv            # То же в CSV
│   ├── security_policy.yaml # Политика прав (настраиваемая)
│   └── TRAINING.md        # Рекомендации по обучению
├── models/
│   └── classifier/        # Обученная модель (TF-IDF + LR)
├── src/
│   ├── api/main.py        # FastAPI сервер
│   ├── classifier/        # ML-классификатор + правила
│   ├── decision/          # Логика allow/confirm/block
│   ├── explain/           # Объяснения с маскированием
│   ├── guard/             # Оркестратор проверки
│   ├── journal/           # Журнал решений
│   ├── policy/            # YAML-политика и движок прав
│   ├── session/           # Сессии диалогов (бонус)
│   ├── adapter/           # Демо-заглушка получателя
│   └── config/            # Настройки
├── scripts/
│   └── train.py           # Обучение модели
├── pyproject.toml         # Зависимости
├── Makefile               # Команды запуска
└── README.md              # Этот файл
```

## Требования

- Python 3.11+
- CPU-only инференс (нет внешних LLM API)
- ≤ 8 vCPU, ≤ 32 GB RAM, ≤ 8 GB VRAM
