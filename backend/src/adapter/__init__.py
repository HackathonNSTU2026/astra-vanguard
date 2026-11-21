from __future__ import annotations

import json
import threading
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC
from pathlib import Path
from typing import Any


@dataclass
class PendingConfirm:
    id: str
    user_id: str
    user_prompt: str
    context: dict[str, Any]
    decision: str
    created_at: str
    confirmed: bool = False


@dataclass
class AdapterRecord:
    id: str
    user_id: str
    user_prompt: str
    decision: str
    received_at: str


class DemoAdapter:
    """Демонстрационный получатель (заглушка) целевого агента."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._pending: dict[str, PendingConfirm] = {}
        self._received: list[AdapterRecord] = []
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding='utf-8'))
                self._received = [AdapterRecord(**r) for r in data.get('received', [])]
                self._pending = {
                    p['id']: PendingConfirm(**p) for p in data.get('pending', [])
                }
            except (json.JSONDecodeError, TypeError, KeyError):
                self._received = []
                self._pending = {}

    def _save(self) -> None:
        data = {
            'received': [asdict(r) for r in self._received],
            'pending': [asdict(p) for p in self._pending.values()],
        }
        self.path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8'
        )

    def can_receive(self, decision: str) -> bool:
        return decision == 'allow'

    def submit_for_confirm(
        self,
        user_id: str,
        user_prompt: str,
        context: dict[str, Any],
        decision: str,
    ) -> str:
        pending_id = str(uuid.uuid4())
        from datetime import datetime

        pending = PendingConfirm(
            id=pending_id,
            user_id=user_id,
            user_prompt=user_prompt,
            context=context,
            decision=decision,
            created_at=datetime.now(UTC).isoformat(),
        )
        with self._lock:
            self._pending[pending_id] = pending
            self._save()
        return pending_id

    def confirm(
        self,
        pending_id: str,
        user_id: str,
        recheck: Callable[[str, dict[str, Any]], bool],
    ) -> bool:
        with self._lock:
            pending = self._pending.get(pending_id)
            if pending is None:
                return False
            if pending.user_id != user_id:
                return False
            if pending.confirmed:
                return False
            if not recheck(pending.user_prompt, pending.context):
                return False
            pending.confirmed = True
            self._received.append(
                AdapterRecord(
                    id=str(uuid.uuid4()),
                    user_id=pending.user_id,
                    user_prompt=pending.user_prompt,
                    decision=pending.decision,
                    received_at=pending.created_at,
                )
            )
            del self._pending[pending_id]
            self._save()
        return True

    def cancel(self, pending_id: str, user_id: str) -> bool:
        with self._lock:
            pending = self._pending.get(pending_id)
            if pending is None or pending.user_id != user_id:
                return False
            del self._pending[pending_id]
            self._save()
        return True

    def list_pending(self, user_id: str) -> list[PendingConfirm]:
        with self._lock:
            return [p for p in self._pending.values() if p.user_id == user_id]

    def received(self) -> list[AdapterRecord]:
        return list(self._received)
