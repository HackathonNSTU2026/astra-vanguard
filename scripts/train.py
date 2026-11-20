"""Обучающий скрипт для классификатора ИИ-сторожа.

Загружает dev.jsonl, обучает TF-IDF + логистическую регрессию,
сохраняет модель для использования в продакшене.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.classifier import Classifier


def load_dev(path: str | Path) -> tuple[list[str], list[str], list[str]]:
    texts: list[str] = []
    categories: list[str] = []
    levels: list[str] = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            texts.append(rec['user_prompt'])
            categories.append(rec['risk_category'])
            levels.append(rec['risk_level'])
    return texts, categories, levels


def main() -> None:
    dev_path = Path('dataset/dev.jsonl')
    model_dir = Path('models/classifier')

    texts, categories, levels = load_dev(dev_path)

    clf = Classifier()
    clf.train(texts, categories, levels)
    clf.save_model(model_dir)

    print(f'Обучено на {len(texts)} примерах. Модель сохранена в {model_dir}')


if __name__ == '__main__':
    main()
