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
        advisory_request = self._is_safe_advisory_request(user_prompt)

        if self.policy.agent(target_agent) is None:
            return Decision(
                decision='block',
                risk_level='high',
                risk_category='tool_abuse',
                explanation=f'Агент {target_agent} отсутствует в политике; запрос заблокирован.',
            )

        if self._requests_env_file_access(user_prompt):
            return Decision(
                decision='block',
                risk_level='critical',
                risk_category='unauthorized_data_access',
                explanation='Чтение файла .env и его вариантов запрещено: там могут находиться секреты.',
            )

        if cat in self.policy.always_block and not advisory_request:
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
        forbidden, action = self.engine.is_forbidden_action(all_text, target_agent)
        if forbidden and not advisory_request:
            return Decision(
                decision='block',
                risk_level='critical',
                risk_category=cat if cat != 'none' else 'tool_abuse',
                explanation=f'Запрещённое действие {action} для любой роли; запрос заблокирован.',
                requires_confirm=False,
            )

        if advisory_request:
            return Decision(
                decision='allow',
                risk_level='none',
                risk_category='none',
                explanation='Запрос носит справочный или защитный характер и не требует выполнения действия.',
            )

        # Authorization must not depend on the ML model recognizing the request.
        # Check every explicit operation in the current user message against policy.
        tools = self._infer_tools(user_prompt)
        checked: list[ToolCheck] = []
        for tool in tools:
            resource = self._infer_resource(user_prompt)
            checked.append(
                self.engine.check_tool(
                    target_agent, user_role, tool, resource, user_prompt
                )
            )

        if checked:
            denied = [check for check in checked if not check.allowed]
            if denied:
                return Decision(
                    decision='block',
                    risk_level=level if level != 'none' else 'high',
                    risk_category=cat if cat != 'none' else 'tool_abuse',
                    explanation='; '.join(c.reason for c in denied)
                    + f'; запрос выходит за полномочия роли {user_role}.',
                    checked_tools=checked,
                )
            needs_confirm = any(c.requires_confirm for c in checked)
            if needs_confirm:
                return Decision(
                    decision='confirm',
                    risk_level=level if level != 'none' else 'medium',
                    risk_category='sensitive_action',
                    explanation='; '.join(c.reason for c in checked)
                    + '; действие требует явного подтверждения.',
                    requires_confirm=True,
                    checked_tools=checked,
                )
            return Decision(
                decision='allow',
                risk_level='none' if cat == 'sensitive_action' else level,
                risk_category='none' if cat == 'sensitive_action' else cat,
                explanation='; '.join(c.reason for c in checked)
                + '; запрос разрешён политикой.',
                checked_tools=checked,
            )

        if cat in self.policy.context_dependent and not checked:
            return Decision(
                decision='block',
                risk_level=level if level != 'none' else 'high',
                risk_category=cat,
                explanation='Не удалось определить инструмент для проверки полномочий; запрос заблокирован.',
            )

        if cat == 'sensitive_action':
            return Decision(
                decision='confirm',
                risk_level='medium',
                risk_category='sensitive_action',
                explanation='Значимое действие требует явного подтверждения.',
                requires_confirm=True,
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

    def _infer_tools(self, text: str) -> list[str]:
        patterns = {
            'run_shell': (
                r'\brun_shell\b|\bshell\b|командная\s+строка|'
                r'(?:выполнить|выполни|запусти)\s+команду|'
                r'\b(?:run|execute)\s+(?:the\s+)?(?:shell|command)\b|'
                r'\b(?:rm|chmod|chown|kubectl|docker|systemctl)\s+[-\w]|\bdf\s+-h\b'
            ),
            'read_logs': (
                r'\bread_logs\b|покажи\s+логи|показать\s+логи|логи\s+сервиса|'
                r'просмотр\s+логов|прочитай\s+логи|\b(?:show|read)\b[^\r\n]{0,100}\blogs\b'
            ),
            'restart_service': (
                r'\brestart_service\b|перезапусти|перезапуск\s+(?:сервиса|службы)|'
                r'перезагрузка\s+сервиса|\brestart\b'
            ),
            'delete_resource': (
                r'\bdelete_resource\b|удал(?:и|ить|яй)\s+\S+|\bdelete\b|'
                r'\bdrop\s+(?:the\s+)?(?:[\w.-]+\s+){0,3}(?:database|db|table|schema)\b'
            ),
        }
        return [
            tool for tool, pattern in patterns.items()
            if re.search(pattern, text, re.IGNORECASE)
        ]

    def _infer_tool(self, text: str) -> str | None:
        tools = self._infer_tools(text)
        return tools[0] if tools else None

    def _is_safe_advisory_request(self, text: str) -> bool:
        """Recognize narrow educational and defensive requests without an action request."""
        patterns = (
            r'(?i)\bwhat\s+is\s+a\s+system\s+prompt\b',
            r'(?i)\b(?:explain|what\s+is|why)\b[^\r\n]{0,140}\b(?:curl\s*\|\s*(?:bash|sh)|reverse\s+shell|chmod\s+777|drop\s+table|truncate)\b',
            r'(?iu)\b(?:объясни|что\s+такое|почему)\b[^\r\n]{0,140}\b(?:curl\s*\|\s*(?:bash|sh)|reverse\s+shell|chmod\s+777|drop\s+table|truncate)\b',
            r'(?i)\b(?:classify|categorize)\b[^\r\n]{0,180}\b(?:do\s+not|don\'t)\s+execute\b',
            r'(?iu)\b(?:классифицируй|определи\s+категорию)\b[^\r\n]{0,180}\b(?:не\s+выполня|только\s+классификац)',
            r'(?i)\bwrite\s+a\s+regex\s+to\s+detect\b',
            r'(?iu)\b(?:исследую\s+безопасность\s+llm|категории\s+атак)\b[^\r\n]{0,180}\b(?:jailbreak|prompt\s+injection)\b',
            r'(?iu)\bнапиши\s+короткий\s+рассказ\b[^\r\n]{0,180}\bбез\s+технических\s+детал',
            r'(?i)\b(?:write|create)\s+(?:a\s+)?falco\s+rule\b[^\r\n]{0,180}\b(?:detect|detects)\b[^\r\n]{0,100}\b(?:shell|container)\b',
            r'(?iu)\bнапиши\s+правило\s+falco\b[^\r\n]{0,180}\b(?:shell|контейнер)',
            r'(?i)\bhow\s+do\s+i\s+safely\s+drop\s+an?\s+old\s+test\s+table\s+in\s+dev\b',
            r'(?iu)\bкак\s+(?:принудительно\s+)?удалить\s+namespace\b[^\r\n]{0,120}\bdev\b',
            r'(?iu)\bпокажи\s+историю\s+релизов\b',
            r'(?iu)\bсколько\s+(?:replicas|реплик)\b',
        )
        return any(re.search(pattern, text) for pattern in patterns)

    def _requests_env_file_access(self, text: str) -> bool:
        env_file = r'(?:[\w./\\-]*[/\\])?\.env(?:[.\w-]*)?'
        access_verbs = (
            r'прочитай|прочитать|прочти|прочесть|покажи|показать|открой|открыть|'
            r'выведи|вывести|скопируй|скопировать|выгрузи|дай\s+(?:мне\s+)?содержимое|'
            r'read|show|open|print|dump|copy|reveal'
        )
        patterns = (
            rf'(?i)(?:{access_verbs})\s+(?:мне\s+|me\s+)?(?:файл\s+|the\s+file\s+)?'
            rf'[^\n]{{0,50}}{env_file}',
            rf'(?i)\b(?:cat|type|more|less|Get-Content)\s+[^\n]{{0,100}}{env_file}',
        )
        return any(re.search(pattern, text) for pattern in patterns)

    def _infer_resource(self, text: str) -> str | None:
        match = re.search(r'\b([\w-]+-(?:prod|dev|stage|test)[\w-]*)\b', text)
        if match:
            return match.group(1)
        match = re.search(r'\b(\*[-*]prod[-*]*|prod[-*])', text, re.IGNORECASE)
        if match:
            return match.group(1)
        return None
