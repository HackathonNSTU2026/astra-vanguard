from __future__ import annotations

from dataclasses import dataclass

from src.policy.environments import detect_environment, environment_signals
from src.policy.models import SecurityPolicy


@dataclass(frozen=True)
class ToolCheck:
    tool: str
    allowed: bool
    requires_confirm: bool
    reason: str


@dataclass(frozen=True)
class PolicyResult:
    allowed: bool
    requires_confirm: bool
    reason: str
    checked_tools: list[ToolCheck] = None  # type: ignore[assignment]


class PolicyEngine:
    """Детерминированная проверка прав на основе YAML-политики.

    Не содержит жёстко зашитой матрицы прав — все правила загружаются из security_policy.yaml.
    """

    def __init__(self, policy: SecurityPolicy) -> None:
        self.policy = policy

    def check_tool(
        self,
        agent_name: str,
        user_role: str,
        tool: str,
        resource: str | None = None,
        env_text: str | None = None,
    ) -> ToolCheck:
        agent = self.policy.agent(agent_name)
        if agent is None:
            return ToolCheck(
                tool=tool,
                allowed=False,
                requires_confirm=False,
                reason=f'Агент {agent_name} не найден в политике',
            )

        if tool not in agent.tools:
            return ToolCheck(
                tool=tool,
                allowed=False,
                requires_confirm=False,
                reason=f'Инструмент {tool} отсутствует в списке разрешённых инструментов агента {agent_name}',
            )

        role_policy = agent.roles.get(user_role)
        if role_policy is None:
            return ToolCheck(
                tool=tool,
                allowed=False,
                requires_confirm=False,
                reason=f'Роль {user_role} не найдена для агента {agent_name}',
            )

        tool_rule = role_policy.tools.get(tool)
        if tool_rule is None:
            return ToolCheck(
                tool=tool,
                allowed=False,
                requires_confirm=False,
                reason=f'Инструмент {tool} не разрешён роли {user_role}',
            )

        # Определяем окружение
        env = None
        has_env_signal = False
        if env_text:
            env = detect_environment(env_text)
            has_env_signal = any(environment_signals(env_text))
        if env is None and resource and not has_env_signal:
            env = detect_environment(resource)

        # Расцениваем правило
        if isinstance(tool_rule, str):
            rule = tool_rule
            conditions: dict[str, str] = {}
        elif isinstance(tool_rule, dict):
            # {prod: confirm, nonprod: allow} или {any: confirm}
            rule = None
            conditions = tool_rule
        else:
            rule = str(tool_rule)
            conditions = {}

        allowed = False
        requires_confirm = False
        reason_parts: list[str] = []

        if rule == 'deny':
            allowed = False
            requires_confirm = False
            reason_parts.append(f'инструмент {tool} запрещён роли {user_role}')
        elif rule == 'allow':
            allowed = True
            requires_confirm = False
            reason_parts.append(f'инструмент {tool} разрешён роли {user_role}')
        elif rule == 'confirm':
            allowed = True
            requires_confirm = True
            reason_parts.append(
                f'инструмент {tool} требует подтверждения для роли {user_role}'
            )
        elif rule == 'any':
            allowed = True
            requires_confirm = False
            reason_parts.append(f'инструмент {tool} разрешён в любом окружении')
        elif rule == 'nonprod':
            if env == 'nonprod':
                allowed = True
                requires_confirm = False
                reason_parts.append(f'инструмент {tool} разрешён в nonprod')
            elif env is None:
                reason_parts.append(
                    f'инструмент {tool}: окружение не определено, правило nonprod не подтверждено'
                )
            else:
                allowed = False
                requires_confirm = False
                reason_parts.append(
                    f'инструмент {tool} запрещён в production для роли {user_role}'
                )
        elif conditions:
            # Условное правило: {prod: confirm, nonprod: allow} или {any: confirm}
            if 'any' in conditions:
                val = conditions['any']
                allowed = val in ('allow', 'confirm')
                requires_confirm = val == 'confirm'
                reason_parts.append(
                    f'инструмент {tool}: {val} в любом окружении для роли {user_role}'
                )
            elif env == 'prod' and 'prod' in conditions:
                val = conditions['prod']
                allowed = val in ('allow', 'confirm')
                requires_confirm = val == 'confirm'
                reason_parts.append(
                    f'инструмент {tool}: {val} в production для роли {user_role}'
                )
            elif env == 'nonprod' and 'nonprod' in conditions:
                val = conditions['nonprod']
                allowed = val in ('allow', 'confirm')
                requires_confirm = val == 'confirm'
                reason_parts.append(
                    f'инструмент {tool}: {val} в nonprod для роли {user_role}'
                )
            elif env is None:
                # Missing or contradictory environment: apply the strictest
                # applicable prod/nonprod rule; absent rules do not grant access.
                vals = [conditions[k] for k in ('prod', 'nonprod') if k in conditions]
                if not vals or any(v not in ('allow', 'confirm', 'deny') for v in vals):
                    allowed = False
                    reason_parts.append(
                        f'инструмент {tool}: нет однозначного правила для окружения'
                    )
                elif 'deny' in vals:
                    reason_parts.append(
                        f'инструмент {tool}: окружение не определено или противоречиво; заблокировано по наиболее строгому правилу'
                    )
                elif 'confirm' in vals:
                    allowed = True
                    requires_confirm = True
                    reason_parts.append(
                        f'инструмент {tool}: окружение не определено или противоречиво; требуется подтверждение'
                    )
                elif len(vals) == 2:
                    allowed = True
                    reason_parts.append(
                        f'инструмент {tool}: разрешено в обоих окружениях'
                    )
                else:
                    reason_parts.append(
                        f'инструмент {tool}: отсутствует правило для второго окружения'
                    )
            else:
                allowed = False
                requires_confirm = False
                reason_parts.append(
                    f'инструмент {tool}: нет правила для окружения {env}'
                )
        else:
            allowed = False
            requires_confirm = False
            reason_parts.append(f'неизвестное правило для инструмента {tool}')

        return ToolCheck(
            tool=tool,
            allowed=allowed,
            requires_confirm=requires_confirm,
            reason='; '.join(reason_parts),
        )

    def check_resource_access(
        self,
        agent_name: str,
        user_role: str,
        resource: str,
        env_text: str | None = None,
    ) -> ToolCheck:
        """Проверка доступа к ресурсу (читение логов и т.д. через run_shell/read_logs)."""
        # Для чтения логов используем тот же инструмент read_logs
        return self.check_tool(agent_name, user_role, 'read_logs', resource, env_text)

    def is_forbidden_action(
        self, text: str, agent_name: str | None = None
    ) -> tuple[bool, str]:
        """Проверяет запрещённые политикой действия независимо от роли."""
        import re

        agent = self.policy.agent(agent_name) if agent_name else None
        agent_actions = (
            agent.forbidden_actions
            if agent is not None
            else [
                action
                for configured_agent in self.policy.agents.values()
                for action in configured_agent.forbidden_actions
            ]
        )
        actions = list(
            dict.fromkeys(
                [
                    *self.policy.forbidden_actions,
                    *agent_actions,
                ]
            )
        )
        action_patterns = {
            'disable_audit_or_wipe_logs': (
                r'\b(?:disable|turn\s+off)\s+(?:audit(?:ing)?|logging)\b',
                r'\b(?:wipe|destroy|delete|erase|remove)\s+(?:security\s+)?logs?\b',
                r'\b(?:отключ(?:и|ить|ите)|выключ(?:и|ить|ите))\s+(?:аудит|логир\w*)',
                r'\b(?:уничтож(?:ь|ить|ьте)|удал(?:и|ить|ите)|стер(?:еть|и))\s+(?:журнал\w*|лог\w*)',
            ),
            'pipe_remote_script_to_shell': (
                r'\b(?:curl|wget)\b[^\r\n|]{0,512}\|\s*(?:bash|sh)\b',
                r'\b(?:download|fetch)\b[^\r\n]{0,160}\b(?:script|installer)\b[^\r\n]{0,160}\b(?:run|execute)\b',
                r'\bзагруз(?:и|ить|ка)\s+удалённ\w*\s+скрипт\w*[^.\r\n]{0,160}(?:запуст|выполн)',
            ),
            'add_ssh_keys_or_sudoers_via_chat': (
                r'\b(?:add|append|install|import)\b[^\r\n]{0,160}\b(?:ssh[-_ ]?key|authorized_keys?)\b',
                r'\b(?:modify|edit|change)\b[^\r\n]{0,160}\bsudoers\b',
                r'\b(?:добав(?:ь|ить|ьте)|установ(?:и|ить|ите)|запиш(?:и|ать|ите))\b[^\r\n]{0,160}\b(?:ssh[-_ ]?(?:ключ|key)|authorized_keys?)\b',
                r'\b(?:измени|изменить|редактируй|редактировать|добавь|добавить)\b[^\r\n]{0,160}\bsudoers\b',
            ),
            'send_secrets_or_data_to_external_hosts': (
                r'\b(?:send|upload|post|exfiltrat\w*)\b[^\r\n]{0,200}\b(?:secrets?|tokens?|logs?|data)\b[^\r\n]{0,200}\b(?:external|outside|third[- ]?party)\b',
                r'\b(?:secrets?|tokens?|logs?|data)\b[^\r\n]{0,200}\b(?:send|upload|post|exfiltrat\w*)\b[^\r\n]{0,200}\b(?:external|outside|third[- ]?party)\b',
                r'\b(?:отправ(?:ь|ить|ьте)|переда(?:й|ть|йте)|выгруз(?:и|ить|ите)|загруз(?:и|ить|ите))\b[^\r\n]{0,200}\b(?:секрет\w*|токен\w*|лог\w*|данн\w*)\b[^\r\n]{0,200}\b(?:внешн\w*|треть(?:ей|я)\s+сторон\w*)',
                r'\b(?:секрет\w*|токен\w*|лог\w*|данн\w*)\b[^\r\n]{0,200}\b(?:отправ(?:ь|ить|ьте)|переда(?:й|ть|йте)|выгруз(?:и|ить|ите)|загруз(?:и|ить|ите))\b[^\r\n]{0,200}\b(?:внешн\w*|треть(?:ей|я)\s+сторон\w*)',
            ),
        }

        for action in actions:
            patterns = action_patterns.get(action, ())
            if any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns):
                return True, action
        return False, ''

    def secret_values_present(self, text: str) -> bool:
        """Признакиpresence secret values (для маскирования и блокировки)."""
        import re

        # Паттерны секретов: ключи, пароли, токены
        patterns = [
            r'(?i)(api[_-]?key|secret|password|token|private[_-]?key|access[_-]?key)\s*[:=]\s*\S+',
            r'AKIA[0-9A-Z]{16}',  # AWS access key
            r'(?i)ssh-rsa\s+\S+',
        ]
        return any(re.search(p, text) for p in patterns)
