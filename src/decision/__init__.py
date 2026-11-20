from __future__ import annotations

import re
from dataclasses import dataclass

from src.classifier import ClassificationResult
from src.policy.engine import PolicyEngine, ToolCheck
from src.policy.models import SecurityPolicy


@dataclass(frozen=True)
class Decision:
    decision: str
    risk_level: str
    risk_category: str
    explanation: str
    requires_confirm: bool = False
    checked_tools: list[ToolCheck] | None = None


class DecisionMaker:
    """Принимает решение allow/confirm/block на основе классификации и политики."""

    def __init__(self, policy: SecurityPolicy) -> None:
        self.policy = policy
        self.engine = PolicyEngine(policy)

    def make(
        self,
        classification: ClassificationResult,
        user_role: str,
        user_prompt: str,
        history: list[dict[str, str]],
        attachments: list[dict[str, str]],
        env_text: str | None = None,
        target_agent: str = 'it_ops_agent',
    ) -> Decision:
        cat = classification.risk_category
        level = classification.risk_level

        if cat in self.policy.always_block:
            return Decision(
                decision='block',
                risk_level=level,
                risk_category=cat,
                explanation=f'Обнаружена атака категории {cat}; роль {user_role} не может её выполнить. Запрос заблокирован политикой.',
                requires_confirm=False,
            )

        all_text = (
            user_prompt
            + '\n'
            + '\n'.join(h.get('content', '') for h in history)
            + '\n'
            + '\n'.join(a.get('content', '') for a in attachments)
        )
        forbidden, action = self.engine.is_forbidden_action(all_text)
        if forbidden:
            return Decision(
                decision='block',
                risk_level='critical',
                risk_category=cat if cat != 'none' else 'tool_abuse',
                explanation=f'Запрещённое действие {action} для любой роли; запрос заблокирован.',
                requires_confirm=False,
            )

        if cat in self.policy.context_dependent:
            tool = self._infer_tool(user_prompt)
            resource = self._infer_resource(user_prompt)
            check = self.engine.check_tool(
                target_agent, user_role, tool, resource, env_text or user_prompt
            )

            if not check.allowed:
                return Decision(
                    decision='block',
                    risk_level=level,
                    risk_category=cat,
                    explanation=f'{check.reason}; запрос выходит за полномочия роли {user_role}.',
                    requires_confirm=False,
                    checked_tools=[check],
                )
            if check.requires_confirm:
                return Decision(
                    decision='confirm',
                    risk_level=level,
                    risk_category='sensitive_action',
                    explanation=f'{check.reason}; действие допустимо, но требует явного подтверждения.',
                    requires_confirm=True,
                    checked_tools=[check],
                )
            return Decision(
                decision='allow',
                risk_level=level,
                risk_category=cat,
                explanation=f'{check.reason}; запрос разрешён в текущем контексте.',
                requires_confirm=False,
                checked_tools=[check],
            )

        if cat == 'sensitive_action':
            tool = self._infer_tool(user_prompt)
            resource = self._infer_resource(user_prompt)
            check = self.engine.check_tool(
                target_agent, user_role, tool, resource, env_text or user_prompt
            )
            if not check.allowed:
                return Decision(
                    decision='block',
                    risk_level=level,
                    risk_category=cat,
                    explanation=f'{check.reason}; роль {user_role} не имеет прав на это действие.',
                    requires_confirm=False,
                    checked_tools=[check],
                )
            return Decision(
                decision='confirm',
                risk_level=level,
                risk_category='sensitive_action',
                explanation=f'Значимое действие для роли {user_role}; требуется явное подтверждение.',
                requires_confirm=True,
                checked_tools=[check],
            )

        if cat == 'none':
            tool = self._infer_tool(user_prompt)
            if tool:
                resource = self._infer_resource(user_prompt)
                check = self.engine.check_tool(
                    target_agent, user_role, tool, resource, env_text or user_prompt
                )
                if not check.allowed:
                    return Decision(
                        decision='block',
                        risk_level='medium',
                        risk_category='tool_abuse',
                        explanation=f'{check.reason}; роль {user_role} не имеет прав на {tool}.',
                        requires_confirm=False,
                        checked_tools=[check],
                    )
                if check.requires_confirm:
                    return Decision(
                        decision='confirm',
                        risk_level='medium',
                        risk_category='sensitive_action',
                        explanation=f'{check.reason}; требуется подтверждение.',
                        requires_confirm=True,
                        checked_tools=[check],
                    )
            return Decision(
                decision='allow',
                risk_level='none',
                risk_category='none',
                explanation='Запрос легитимен и разрешён в текущем контексте.',
                requires_confirm=False,
            )

        return Decision(
            decision='block',
            risk_level=level,
            risk_category=cat,
            explanation=f'Категория {cat} не распознана как разрешённая; консервативная блокировка.',
            requires_confirm=False,
        )

    def _infer_tool(self, text: str) -> str | None:
        patterns = {
            'run_shell': r'\brun_shell\b|выполнить\s+команду|shell|командная\s+строка',
            'read_logs': r'\bread_logs\b|покажи\s+логи|логи\s+сервиса|просмотр\s+логов',
            'restart_service': r'\brestart_service\b|перезапусти|перезагрузка\s+сервиса|restart',
            'delete_resource': r'\bdelete_resource\b|удали\s+ресурс|удалить|delete',
        }
        for tool, pat in patterns.items():
            if re.search(pat, text, re.IGNORECASE):
                return tool
        return None

    def _infer_resource(self, text: str) -> str | None:
        match = re.search(r'\b([\w-]+-(?:prod|dev|stage|test)[\w-]*)\b', text)
        if match:
            return match.group(1)
        match = re.search(r'\b(\*[-*]prod[-*]*|prod[-*])', text, re.IGNORECASE)
        if match:
            return match.group(1)
        return None
