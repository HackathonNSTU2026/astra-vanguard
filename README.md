# astra-vanguard

Решение кейса «ИИ-сторож» — guardians для DevOps-ассистента `it_ops_agent`. Проект на Python 3.10+, только стандартная библиотека.

## Структура проекта

```
astra-vanguard/
├── README.md                      # этот файл
├── LICENSE
├── .gitignore
├── docs/
│   ├── ИИ-сторож_документ.pdf     # документация проекта
│   └── ИИ-сторож_презентация.pdf  # презентация проекта
└── dataset/                       # данные, политика, API-заглушка, оценщик
    ├── security_policy.yaml       # политика безопасности: категории always_block / context_dependent,
    │                               # роли и права агента it_ops_agent, forbidden_actions
    ├── starter_api.py             # минимальный HTTP-контракт API (POST /v1/check), функция-заглушка check()
    ├── evaluate.py                # публичный evaluator v2 (только stdlib): cost-скора, p95 latency,
    │                               # precision/recall/F1, матрица ошибок, штрафы за latency
    ├── test_evaluate.py           # юнит-тесты unittest для score из evaluate.py
    ├── dev.jsonl                  # публичный набор данных (JSONL): id, user_prompt, context,
    │                               # is_dangerous, risk_level, risk_category, expected_decision, ...
    ├── dev.csv                    # тот же набор в CSV-формате
    └── TRAINING.md                # инструкция как начать: разделение данных, фичи, baseline, дообучение,
    │                               # пороги, подключение к API, Google Colab
```

## Что в каком файле

| Файл | Содержание |
|------|------------|
| `dataset/security_policy.yaml` | Политика безопасности. Решения: `allow`, `confirm`, `block`. Категории `always_block` (блокируются всегда), `context_dependent` (зависят от роли и окружения), роли `developer/sre/admin` с правами на инструменты и среды, `forbidden_actions`. Решение должно читать правила из YAML, а не хардкодить. |
| `dataset/starter_api.py` | HTTP-сервер на `BaseHTTPServer`. Эндпоинт `POST /v1/check` с `user_prompt` и `context`. Заглушка `check()` всегда возвращает `confirm` — заменить на собственное решение. |
| `dataset/evaluate.py` | Оценщик качества v2: сбалансированный cost-скора, p95 задержки, precision/recall/F1, макро-F1, матрица ошибок, штрафы за latency (>3000/6000 мс), gate на высококритичных примерах (≥85% block), cpu_bonus. |
| `dataset/test_evaluate.py` | Тесты для `evaluate.score`: идеальный прогноз, confirm не проходит, инвалиды/таймауты, границы latency, allow/block. |
| `dataset/dev.jsonl` | Публичный тренировочный/валидационный набор. Поля: `id`, `user_prompt`, `context` (target_agent, user_role, user_id, user_name, system_prompt, history, attachments), `is_dangerous`, `risk_level`, `risk_category`, `expected_decision`, `lang`, `difficulty`, `tags`. |
| `dataset/dev.csv` | Тот же набор в CSV. |
| `dataset/TRAINING.md` | Гайд как начать: чтение политики, разделение данных, фичи только из API-входа, CPU-baseline (TF-IDF + линейный классификатор), дообучение энкодера/LLM с LoRA, пороги, подключение к API, Google Colab. |
