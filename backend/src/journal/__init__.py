from __future__ import annotations

import json
import threading
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.explain import Explainer


@dataclass
class JournalEntry:
    id: str
    timestamp: str
    user_role: str
    user_id: str | None
    decision: str
    risk_category: str
    risk_level: str
    latency_ms: float
    policy_version: int
    user_prompt_masked: str
    explanation: str


class Journal:
    """Журнал решений для последующего анализа.

    Не записывает значения секретов; содержимое маскируется.
    """

    def __init__(self, path: str | Path, policy_version: int = 1) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.policy_version = policy_version
        self._entries: list[JournalEntry] = []
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                with open(self.path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        data = json.loads(line)
                        self._entries.append(JournalEntry(**data))
            except (json.JSONDecodeError, TypeError):
                self._entries = []

    def add(
        self,
        user_role: str,
        user_id: str | None,
        decision: str,
        risk_category: str,
        risk_level: str,
        latency_ms: float,
        user_prompt: str,
        explanation: str,
    ) -> JournalEntry:
        entry = JournalEntry(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC).isoformat(),
            user_role=user_role,
            user_id=user_id,
            decision=decision,
            risk_category=risk_category,
            risk_level=risk_level,
            latency_ms=round(latency_ms, 3),
            policy_version=self.policy_version,
            user_prompt_masked=Explainer().mask_content(user_prompt),
            explanation=explanation,
        )
        with self._lock:
            self._entries.append(entry)
            self._append(entry)
        return entry

    def _append(self, entry: JournalEntry) -> None:
        with open(self.path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(asdict(entry), ensure_ascii=False) + '\n')

    def entries(
        self, limit: int | None = None, filters: dict[str, Any] | None = None
    ) -> list[JournalEntry]:
        result = list(self._entries)
        if filters:
            for key, val in filters.items():
                result = [e for e in result if getattr(e, key, None) == val]
        if limit:
            result = result[-limit:]
        return result

    def clear(self) -> None:
        with self._lock:
            self._entries = []
            if self.path.exists():
                self.path.unlink()
