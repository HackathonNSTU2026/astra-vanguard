from __future__ import annotations

import json
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path


@dataclass
class Message:
    role: str
    content: str
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass
class Session:
    id: str
    user_id: str
    messages: list[Message] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    max_messages: int = 100
    max_age_hours: int = 24

    def add(self, role: str, content: str) -> None:
        self.messages.append(Message(role=role, content=content))
        self.updated_at = datetime.now(UTC).isoformat()
        if len(self.messages) > self.max_messages:
            self.messages = self.messages[-self.max_messages :]

    def to_context_history(self) -> list[dict[str, str]]:
        return [{'role': m.role, 'content': m.content} for m in self.messages]

    def is_expired(self) -> bool:
        updated = datetime.fromisoformat(self.updated_at)
        return datetime.now(UTC) - updated > timedelta(hours=self.max_age_hours)


class SessionManager:
    """Управление изолированными сессиями диалогов (бонус)."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._sessions: dict[str, Session] = {}
        self._user_sessions: dict[str, list[str]] = {}
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding='utf-8'))
                for sid, sdata in data.get('sessions', {}).items():
                    msgs = [Message(**m) for m in sdata.get('messages', [])]
                    session = Session(
                        id=sid,
                        user_id=sdata.get('user_id', ''),
                        messages=msgs,
                        created_at=sdata.get('created_at', ''),
                        updated_at=sdata.get('updated_at', ''),
                        max_messages=sdata.get('max_messages', 100),
                        max_age_hours=sdata.get('max_age_hours', 24),
                    )
                    self._sessions[sid] = session
                    self._user_sessions.setdefault(session.user_id, []).append(sid)
            except (json.JSONDecodeError, TypeError, KeyError):
                self._sessions = {}
                self._user_sessions = {}

    def _save(self) -> None:
        data = {
            'sessions': {
                sid: {
                    **asdict(s),
                    'messages': [asdict(m) for m in s.messages],
                }
                for sid, s in self._sessions.items()
            }
        }
        self.path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8'
        )

    def create(self, user_id: str) -> str:
        with self._lock:
            sid = str(uuid.uuid4())
            session = Session(id=sid, user_id=user_id)
            self._sessions[sid] = session
            self._user_sessions.setdefault(user_id, []).append(sid)
            self._save()
        return sid

    def get(self, session_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def get_for_user(self, user_id: str) -> list[Session]:
        with self._lock:
            return [
                self._sessions[sid]
                for sid in self._user_sessions.get(user_id, [])
                if sid in self._sessions
            ]

    def add_message(self, session_id: str, role: str, content: str) -> bool:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return False
            session.add(role, content)
            self._save()
        return True

    def history(self, session_id: str) -> list[dict[str, str]]:
        session = self.get(session_id)
        if session is None:
            return []
        return session.to_context_history()

    def clear(self, session_id: str, user_id: str) -> bool:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.user_id != user_id:
                return False
            session.messages = []
            session.updated_at = datetime.now(UTC).isoformat()
            self._save()
        return True

    def delete(self, session_id: str, user_id: str) -> bool:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.user_id != user_id:
                return False
            del self._sessions[session_id]
            if user_id in self._user_sessions:
                self._user_sessions[user_id] = [
                    s for s in self._user_sessions[user_id] if s != session_id
                ]
            self._save()
        return True

    def cleanup_expired(self) -> int:
        with self._lock:
            expired = [sid for sid, s in self._sessions.items() if s.is_expired()]
            for sid in expired:
                session = self._sessions[sid]
                uid = session.user_id
                del self._sessions[sid]
                if uid in self._user_sessions:
                    self._user_sessions[uid] = [
                        s for s in self._user_sessions[uid] if s != sid
                    ]
            if expired:
                self._save()
        return len(expired)
