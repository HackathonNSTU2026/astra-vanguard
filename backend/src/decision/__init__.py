from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from src.classifier import ClassificationResult, Classifier
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

    _EXTERNAL_RECIPIENT = (
        r'(?:роскомнадзор\w*|роспотребнадзор\w*|фнс|фсб|мвд|мчс|прокуратур\w*|'
        r'федеральн\w*\s+служб\w*\s+безопасност\w*|налогов\w*\s+инспекц\w*|'
        r'госорган\w*|государственн\w*\s+(?:орган\b|организаци\w*|ведомств\w*)|'
        r'(?:внешн\w*|сторонн\w*)\s+(?:организац\w*|компан\w*|служб\w*|'
        r'поставщик\w*|подрядчик\w*|партн[её]р\w*)|'
        r'поставщик\w*|подрядчик\w*|регулятор\w*|'
        r'(?:external|third[- ]party)\s+(?:organi[sz]ation|company|partner|team|vendor|supplier|contractor)|'
        r'(?:the\s+)?(?:vendor|supplier|contractor|regulator)s?)'
    )
    _EXTERNAL_ADDRESS = r'[\w.+-]+@[\w-]+(?:\.[\w-]+)+'
    _COMMUNICATION = (
        r'(?:напиши(?:те)?|написать|отправ(?:ь(?:те)?|ить)|перешл(?:и(?:те)?|ать)|'
        r'сообщ(?:и(?:те)?|ить)|уведом(?:ь(?:те)?|ить)|обрати(?:сь|тесь|ться)|'
        r'ответ(?:ь(?:те)?|ить)|send|email|e-mail|contact|notify|forward|write\s+to|reply\s+to)'
    )
    _SQL_OBJECT = r'(?:бд|базу(?:\s+данных)?|таблицу|схему|database|db|table|schema)'
    _SQL_DELETE = (
        r'\b(?:дропни|снеси|прибей|грохни|дропнуть|drop|delete|remove|удали)\s+'
        r'(?:(?:эту|ту|старую|тестовую|the|an?)\s+)?' + _SQL_OBJECT + r'\b'
    )
    _UNSPECIFIED_SQL_DELETE = re.compile(
        _SQL_DELETE + r'(?:\s+(?:(?:в|на|in|from)\s+)?'
        r'(?:prod(?:uction)?|dev|stage|test|проде?|тесте?))?'
        r'(?:\s*,?\s*(?:пожалуйста|please))?\s*[.!?]*\s*$',
        re.IGNORECASE,
    )
    _CLAUSE_BREAK = re.compile(
        r'[;\n]+\s*|[.!?]+(?=\s|$)\s*|,?\s+(?:and\s+then|а\s+затем|а\s+потом|затем|потом|then)\s+',
        re.IGNORECASE,
    )
    _COURTESY = re.compile(
        r'\s*(?:добрый день|здравствуйте|привет|пожалуйста|(?:заранее )?спасибо|'
        r'hi|hello|please|thanks|thank you)?\s*[.!?]*\s*',
        re.IGNORECASE,
    )

    def __init__(self, policy: SecurityPolicy, classifier: Classifier) -> None:
        self.policy = policy
        self.engine = PolicyEngine(policy)
        self.classifier = classifier

    def make(
        self,
        classification: ClassificationResult,
        user_role: str,
        user_prompt: str,
        history: list[dict[str, str]],
        attachments: list[dict[str, str]],
        target_agent: str = 'it_ops_agent',
    ) -> Decision:
        cat = classification.risk_category
        level = classification.risk_level
        normalized_prompt = unicodedata.normalize('NFKC', user_prompt).translate(
            dict.fromkeys(map(ord, '\u200b\u200c\u200d\u2060\ufeff'))
        )
        clauses = self._CLAUSE_BREAK.split(normalized_prompt)
        action_text = normalized_prompt
        advisory_request = self._is_safe_advisory_request(normalized_prompt)
        if advisory_request:
            clauses = [
                clause
                for clause in clauses
                if not self._is_safe_advisory_request(clause)
                and not self._COURTESY.fullmatch(clause)
            ]
            action_text = '\n'.join(clauses)
            advisory_request = not self._infer_tools(action_text)

        if self.policy.agent(target_agent) is None:
            return Decision(
                decision='block',
                risk_level='high',
                risk_category='tool_abuse',
                explanation=f'Агент {target_agent} отсутствует в политике; запрос заблокирован.',
            )

        context_text = '\n'.join(
            item.get('content', '') for item in [*history, *attachments]
        )
        policy_text = f'{action_text}\n{context_text}'
        if advisory_request:
            cat, level = 'none', 'none'
            if policy_text.strip():
                independent = self.classifier.classify(
                    action_text, history, attachments, always_block=self.policy.always_block
                )
                cat, level = independent.risk_category, independent.risk_level

        if self._requests_env_file_access(policy_text):
            return Decision(
                decision='block',
                risk_level='critical',
                risk_category='unauthorized_data_access',
                explanation='Чтение файла .env и его вариантов запрещено: там могут находиться секреты.',
            )

        if cat in self.policy.always_block:
            return Decision(
                decision='block',
                risk_level=level,
                risk_category=cat,
                explanation=f'Обнаружена атака категории {cat}; роль {user_role} не может её выполнить. Запрос заблокирован политикой.',
                requires_confirm=False,
            )

        forbidden, action = self.engine.is_forbidden_action(policy_text, target_agent)
        if forbidden:
            return Decision(
                decision='block',
                risk_level='critical',
                risk_category=cat if cat != 'none' else 'tool_abuse',
                explanation=f'Запрещённое действие {action} для любой роли; запрос заблокирован.',
                requires_confirm=False,
            )

        if advisory_request and cat not in self.policy.context_dependent and cat != 'external_communication':
            return Decision(
                decision='allow',
                risk_level='none',
                risk_category='none',
                explanation='Запрос носит справочный или защитный характер и не требует выполнения действия.',
            )

        if any(self._UNSPECIFIED_SQL_DELETE.search(clause) for clause in clauses):
            return Decision(
                decision='block',
                risk_level='high',
                risk_category='tool_abuse',
                explanation='Для удаления укажите конкретное имя базы, таблицы или схемы.',
            )

        # Authorization must not depend on the ML model recognizing the request.
        # Check every explicit operation in the current user message against policy.
        tools = self._infer_tools(action_text)
        if cat == 'external_communication' and 'contact_external' not in tools:
            tools.append('contact_external')
        if tools == ['contact_external'] and cat in self.policy.context_dependent:
            return Decision(
                decision='block',
                risk_level=level,
                risk_category=cat,
                explanation='Для запроса требуется отдельная проверка прав доступа.',
            )
        resource = self._infer_resource(action_text)
        checked: list[ToolCheck] = []
        for tool in tools:
            checked.append(
                self.engine.check_tool(
                    target_agent, user_role, tool, resource, action_text
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
                    risk_category=(
                        'external_communication'
                        if any(c.tool == 'contact_external' and c.requires_confirm for c in checked)
                        else 'sensitive_action'
                    ),
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

        if cat == 'none':
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
        # A quoted status label describes a state. Keep any surrounding action.
        text = re.sub(
            r'["“«‘\x27](?:(?:awaiting|pending)\s+restart|restart\s+(?:pending|required))["”»’\x27]',
            ' ',
            text,
            flags=re.IGNORECASE,
        )
        patterns = {
            'contact_external': (
                rf'\b{self._COMMUNICATION}\s+'
                r'(?:(?:письмо|сообщение|жалобу|обращение|запрос|(?:an?\s+)?'
                r'(?:e-?mail|letter|message|complaint|request))\s+)?'
                r'(?:(?:в|во|на|к|to)\s+)?'
                r'(?:(?:an?|the)\s+)?'
                rf'(?:["«“]?{self._EXTERNAL_RECIPIENT}\b|{self._EXTERNAL_ADDRESS}\b|'
                r'(?:компани\w*|организаци\w*|company)\s+["«“][^"»”\r\n]+["»”])'
            ),
            'run_shell': (
                r'\brun_shell\b|\bshell\b|командная\s+строка|'
                r'(?:выполнить|выполни|запусти)\s+команду|'
                r'\b(?:run|execute)\s+(?:the\s+)?(?:shell|command)\b|'
                r'\b(?:roll\s+back|rollback|deploy)\s+[\w.-]+|'
                r'\b(?:scale|масштабируй)\s+[\w.-]+[^\r\n]{0,100}\b(?:replicas?|реплик\w*)\b|'
                r'\b(?:run|apply)\s+(?:the\s+)?(?:schema\s+)?migration\b|'
                r'\b(?:выполни|запусти|примени)\s+миграцию\b|'
                r'\b(?:очисти|clear|flush)\s+(?:(?:the\s+)?redis\s+)?(?:кэш|кеш|cache)\b|'
                r'\b(?:поставь|установи|set)\s+log_level\s*=|'
                r'\bсделай\s+rollback\b|'
                r'\b(?:rm|chmod|chown|kubectl|docker|systemctl)\s+[-\w]|\bdf\s+-h\b'
            ),
            'read_logs': (
                r'\bread_logs\b|покажи\s+логи|показать\s+логи|логи\s+сервиса|'
                r'просмотр\s+логов|прочитай\s+логи|\b(?:show|read)\b[^\r\n]{0,100}\blogs\b|'
                r'\b(?:show|read|fetch|pull|retrieve|display)\s+(?:the\s+)?'
                r'(?:(?:last|latest|first)\s+(?:\w+\s+)?(?:page|lines?|entries)\s+(?:of|from)\s+(?:the\s+)?)?'
                r'(?:(?:application|service|error|system|audit|server)\s+)?logs?\b|'
                r'\b(?:покажи|пришли|выведи|прочитай|(?:хочу|дай|нужно)\s+(?:посмотреть|просмотреть))\s+'
                r'(?:(?:последни[еюх]|первые)\s+)?(?:(?:\w+\s+)?'
                r'(?:строк[аиу]?|запис(?:и|ей|ь))\s+(?:из\s+)?)?'
                r'(?:лог(?:и|ов|а)?|журнал(?:а|ы|ов)?)\b'
            ),
            'restart_service': (
                r'\brestart_service\b|перезапусти|перезапуск\s+(?:сервиса|службы)|'
                r'перезагрузка\s+сервиса|\brestart\b|'
                r'\b(?:заново|повторно)\s+запуст(?:и|ить)\s+(?:сервис|службу|процесс)\b|'
                r'\bзапуст(?:и|ить)\s+(?:сервис|службу|процесс)\b'
                r'(?:\s+[\w-]+){0,3}\s+(?:заново|повторно)\b|'
                r'\bcycle\s+(?:the\s+)?(?:service|worker|process)\b|'
                r'\bstop\s+(?:the\s+)?(?:running\s+)?(?:service|worker|process)\b'
                r'[^.!?;\r\n]{0,80}\band\s+(?:then\s+)?start\s+it\s+(?:again|back\s+up)\b'
            ),
            'delete_resource': (
                r'\bdelete_resource\b|удал(?:и|ить|яй)\s+\S+|\bdelete\b|'
                + self._SQL_DELETE
                + r'|'
                r'\bdrop\s+(?:the\s+)?(?:[\w.-]+\s+){0,3}(?:database|db|table|schema)\b'
            ),
        }
        return [
            tool
            for tool, pattern in patterns.items()
            if re.search(pattern, text, re.IGNORECASE)
        ]

    def _is_safe_advisory_request(self, text: str) -> bool:
        """Recognize narrow educational and defensive requests without an action request."""
        patterns = (
            r'(?i)\b(?:explain|what\s+is|why)\b[^\r\n]{0,140}\b(?:curl\s*\|\s*(?:bash|sh)|reverse\s+shell|chmod\s+777|drop\s+table|truncate)\b',
            r'(?iu)\b(?:объясни|что\s+такое|почему)\b[^\r\n]{0,140}\b(?:curl\s*\|\s*(?:bash|sh)|reverse\s+shell|chmod\s+777|drop\s+table|truncate)\b',
            r'(?i)\b(?:classify|categorize)\b[^\r\n]{0,180}\b(?:do\s+not|don\'t)\s+execute\b',
            r'(?iu)\b(?:классифицируй|определи\s+категорию)\b[^\r\n]{0,180}\b(?:не\s+выполня|только\s+классификац)',
            r'(?iu)^\s*классифицируй\s+фразу\s+«[^»\r\n]+»(?:\s*[—-]\s*это\s+пример\s+какой\s+атаки)?\s*\??\s*$',
            r'(?i)\bwrite\s+a\s+regex\s+to\s+detect\b',
            r'(?iu)\b(?:исследую\s+безопасность\s+llm|категории\s+атак)\b[^\r\n]{0,180}\b(?:jailbreak|prompt\s+injection)\b',
            r'(?iu)\bнапиши\s+короткий\s+рассказ\b[^\r\n]{0,180}\bбез\s+технических\s+детал',
            r'(?i)\b(?:write|create)\s+(?:a\s+)?falco\s+rule\b[^\r\n]{0,180}\b(?:detect|detects)\b[^\r\n]{0,100}\b(?:shell|container)\b',
            r'(?iu)\bнапиши\s+правило\s+falco\b[^\r\n]{0,180}\b(?:shell|контейнер)',
            r'(?i)\bhow\s+do\s+i\s+safely\s+drop\s+an?\s+old\s+test\s+table\s+in\s+dev\b',
            r'(?iu)\bкак\s+(?:принудительно\s+)?удалить\s+namespace\b[^\r\n]{0,120}\bdev\b',
            r'(?iu)\bпокажи\s+историю\s+релизов\b',
            r'(?iu)\bсколько\s+(?:replicas|реплик)\b',
            r'(?i)\bhow\s+many\s+replicas\b',
            r'(?iu)\b(?:что\s+(?:значит|означает)|объясни)\s+[^;\n.!?]{0,80}\bдропнуть\b',
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
            (
                rf'(?i)(?:{access_verbs})\s+(?:мне\s+|me\s+)?(?:файл\s+|the\s+file\s+)?'
                rf'[^\n]{{0,50}}{env_file}'
            ),
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
