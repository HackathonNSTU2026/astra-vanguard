"""Evaluate the guard with similar prompts held out together across five folds."""

import json
from dataclasses import asdict
from pathlib import Path
from tempfile import TemporaryDirectory

from scipy.sparse.csgraph import connected_components
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import StratifiedGroupKFold
from train import load_training_data

from src.config.settings import load_settings
from src.evaluate.evaluate import load_jsonl, score
from src.guard import Guard


def main() -> None:
    dataset = Path(__file__).resolve().parents[1] / 'dataset'
    rows = load_jsonl(dataset / 'dev.jsonl') + load_jsonl(
        dataset / 'generalization_train.jsonl'
    )
    features = TfidfVectorizer(analyzer='char', ngram_range=(3, 5)).fit_transform(
        row['user_prompt'].casefold() for row in rows
    )
    similarity = features @ features.T
    similarity.data[similarity.data < 0.62] = 0
    similarity.eliminate_zeros()
    n_groups, groups = connected_components(similarity, directed=False)
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=82)
    labels = [row['expected_decision'] for row in rows]
    predictions = []

    with TemporaryDirectory() as directory:
        root = Path(directory)
        settings = load_settings(
            dataset / 'security_policy.yaml', root / 'journal.jsonl'
        )
        for training, validation in splitter.split(groups, labels, groups):
            train_path = root / 'train.jsonl'
            train_path.write_text(
                ''.join(json.dumps(rows[i]) + '\n' for i in training), encoding='utf-8'
            )
            guard = Guard(settings)
            guard.classifier.train(*load_training_data(train_path))
            for i in validation:
                row = rows[i]
                result = guard.check(row['user_prompt'], row['context'])
                predictions.append({'id': row['id'], **asdict(result)})

    report = score(rows, predictions)
    report.update(prompt_groups=int(n_groups), measurement_mode='grouped_offline')
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
