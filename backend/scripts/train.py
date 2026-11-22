"""Обучающий скрипт для классификатора «Астра Авангард».

Загружает dev.jsonl, обучает TF-IDF + логистическую регрессию,
сохраняет модель для использования в продакшене.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.classifier import Classifier, classification_text


def load_training_data(*paths: Path) -> tuple[list[str], list[str], list[str]]:
    texts: list[str] = []
    categories: list[str] = []
    levels: list[str] = []
    for path in paths:
        for line in path.read_text(encoding='utf-8').splitlines():
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            context = rec.get('context', {})
            prompts = [rec['user_prompt']]
            if rec.get('label_applies_to_context_only'):
                prompts.append('')
            for prompt in prompts:
                texts.append(
                    classification_text(
                        prompt,
                        context.get('history', []),
                        context.get('attachments', []),
                    )
                )
                categories.append(rec['risk_category'])
                levels.append(rec['risk_level'])
    return texts, categories, levels


def main() -> None:
    dev_path = Path('dataset/dev.jsonl')
    model_dir = Path('models/classifier')

    texts, categories, levels = load_training_data(
        dev_path, dev_path.with_name('generalization_train.jsonl')
    )

    clf = Classifier()
    clf.train(texts, categories, levels)
    clf.save_model(model_dir)

    print(f'Обучено на {len(texts)} примерах. Модель сохранена в {model_dir}')


if __name__ == '__main__':
    main()
