.PHONY: lint update

PY := uv run
RUFF := uvx ruff

run_server:
	uv run python ./src/api/main.py

run_evaluate:
	uv run python ./src/evaluate/evaluate.py --data dataset/dev.jsonl --endpoint http://127.0.0.1:8000/v1/check

lint:
	$(RUFF) check --fix api/ dataset/
	$(RUFF) format api/ dataset/

update:
	uv sync -U
	uv pip compile pyproject.toml -o requirements.txt
	uv pip compile --dev pyproject.toml -o requirements-dev.txt
