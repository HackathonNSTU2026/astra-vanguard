from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    policy_path: Path
    journal_path: Path
    sessions_path: Path
    adapter_path: Path
    host: str = '127.0.0.1'
    port: int = 8000
    max_body_size: int = 1048576  # 1 MiB
    model_dir: Path | None = None
    policy_reload: bool = True


def load_settings(
    policy_path: str | Path = 'dataset/security_policy.yaml',
    journal_path: str | Path = 'data/journal.jsonl',
    sessions_path: str | Path = 'data/sessions.json',
    adapter_path: str | Path = 'data/adapter.json',
    **kwargs: object,
) -> Settings:
    return Settings(
        policy_path=Path(policy_path),
        journal_path=Path(journal_path),
        sessions_path=Path(sessions_path),
        adapter_path=Path(adapter_path),
        **kwargs,  # type: ignore[arg-type]
    )
