from __future__ import annotations

import re

from src.decision import Decision


class Explainer:
    """Генерирует финальное объяснение решения."""

    # ruff: noqa: RUF012 — константы не мутируют

    SECRET_PATTERNS = [
        re.compile(
            r'(?i)(api[_-]?key|secret|password|token|private[_-]?key)\s*[:=]\s*\S+',
            re.IGNORECASE,
        ),
        re.compile(r'AKIA[0-9A-Z]{16}'),
        re.compile(r'(?i)ssh-rsa\s+\S+'),
    ]

    def explain(
        self, decision: Decision, user_role: str, env: str | None = None
    ) -> str:
        base = decision.explanation
        parts: list[str] = [base]
        parts.append(f'Роль: {user_role}.')
        if env:
            parts.append(f'Окружение: {env}.')
        else:
            parts.append('Окружение: не указано явно (проверьте префиксы ресурсов).')
        parts.append(f'Решение: {decision.decision.upper()}.')
        if decision.requires_confirm:
            parts.append('Требуется явное подтверждение перед передачей агенту.')

        explanation = ' '.join(parts)
        return self._mask_secrets(explanation)

    def _mask_secrets(self, text: str) -> str:
        for pat in self.SECRET_PATTERNS:
            text = pat.sub('[SECRET MASKED]', text)
        return text

    def mask_content(self, text: str) -> str:
        masked = self._mask_secrets(text)
        return masked[:500] + ('...' if len(masked) > 500 else '')
