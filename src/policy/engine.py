from __future__ import annotations

from dataclasses import dataclass

from src.policy.environments import detect_environment
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
        if env_text:
            env = detect_environment(env_text)
        if env is None and resource:
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
            if env == 'nonprod' or env is None:
                allowed = True
                requires_confirm = False
                reason_parts.append(f'инструмент {tool} разрешён в nonprod')
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
                allowed = val != 'deny'
                requires_confirm = val == 'confirm'
                reason_parts.append(
                    f'инструмент {tool}: {val} в любом окружении для роли {user_role}'
                )
            elif env == 'prod' and 'prod' in conditions:
                val = conditions['prod']
                allowed = val != 'deny'
                requires_confirm = val == 'confirm'
                reason_parts.append(
                    f'инструмент {tool}: {val} в production для роли {user_role}'
                )
            elif env == 'nonprod' and 'nonprod' in conditions:
                val = conditions['nonprod']
                allowed = val != 'deny'
                requires_confirm = val == 'confirm'
                reason_parts.append(
                    f'инструмент {tool}: {val} в nonprod для роли {user_role}'
                )
            elif env is None:
                # Неоднозначное окружение — консервативно: require confirm если есть confirm в условиях
                vals = set(conditions.values())
                if 'deny' in vals:
                    allowed = False
                    requires_confirm = False
                    reason_parts.append(
                        f'инструмент {tool}: окружение不明, консервативно блокировано'
                    )
                elif 'confirm' in vals:
                    allowed = True
                    requires_confirm = True
                    reason_parts.append(
                        f'инструмент {tool}: окружение不明, требуется подтверждение'
                    )
                else:
                    allowed = True
                    requires_confirm = False
                    reason_parts.append(f'инструмент {tool}: разрешено (окружение不明)')
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

    def is_forbidden_action(self, text: str) -> tuple[bool, str]:
        """Проверяет, содержит ли текст запрещённое действие для любой роли."""
        text_lower = text.lower()
        for action in self.policy.forbidden_actions:
            action_keywords = {
                'disable_audit_or_wipe_logs': [
                    'отключить аудит',
                    'уничтожить логи',
                    'удалить логи',
                    'wipe logs',
                    'disable audit',
                ],
                'pipe_remote_script_to_shell': [
                    'curl',
                    '| bash',
                    '| sh',
                    'загрузка удалённого скрипта',
                    'немедленным запуском',
                ],
                'add_ssh_keys_or_sudoers_via_chat': [
                    'ssh-ключ',
                    'sudoers',
                    'добавить ssh',
                    'ssh key',
                ],
                'send_secrets_or_data_to_external_hosts': [
                    'отправить секрет',
                    'секрет на внешний',
                    'exfiltration',
                    'внешний адрес',
                ],
            }
            keywords = action_keywords.get(action, [action])
            if any(kw in text_lower for kw in keywords):
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
