.PHONY: run_server run_evaluate run_train lint update clean

PY := uv run
RUFF := uvx ruff

TEMP_DIR := ./temp

run_server:
	$(PY) -m src.api.main --host 0.0.0.0 --port 8000

run_evaluate:
	$(PY) ./src/evaluate/evaluate.py \
		--data ./dataset/dev.jsonl \
		--endpoint http://127.0.0.1:8000/v1/check \
		--report $(TEMP_DIR)/report.json \
		--save-predictions $(TEMP_DIR)/predictions.jsonl

run_train:
	$(PY) scripts/train.py

lint:
	$(RUFF) check --fix src/ scripts/
	$(RUFF) format src/ scripts/

update:
	uv sync -U
	uv pip compile pyproject.toml -o requirements.txt

clean:
	rm -rf $(TEMP_DIR) ./models/
