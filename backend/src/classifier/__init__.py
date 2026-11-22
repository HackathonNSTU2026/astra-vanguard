from __future__ import annotations

import re
import unicodedata
from collections.abc import Collection
from dataclasses import dataclass, field
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

from src.config.settings import Settings

_REQUEST_OPENING = re.compile(
    r'^(?:(?:hello|hey|hi|quick question|добрый день|привет|здравствуйте|слушай|вопрос)'
    r'[!,:.]+\s*)+',
    re.IGNORECASE,
)
_REQUEST_CLOSING = re.compile(
    r'(?<!\s)(?:\s+(?:thank you|thanks|please|заранее спасибо|спасибо|пожалуйста)[!.]*){1,3}$',
    re.IGNORECASE,
)


_NON_ATTACK_CATEGORIES = {'none', 'sensitive_action', 'external_communication'}


def classification_text(
    user_prompt: str,
    history: list[dict[str, str]],
    attachments: list[dict[str, str]],
) -> str:
    # Keep stock greetings out of TF-IDF features at training and inference.
    prompt = _REQUEST_OPENING.sub('', user_prompt.strip())
    parts = [f'current request: {_REQUEST_CLOSING.sub("", prompt)}']
    parts.extend(
        f'history {entry.get("role", "")}: {entry.get("content", "")}'
        for entry in history
    )
    parts.extend(f'attachment: {entry.get("content", "")}' for entry in attachments)
    return '\n'.join(parts)


@dataclass(frozen=True)
class ClassificationResult:
    risk_category: str
    risk_level: str
    confidence: float
    is_attack: bool
    detected_tools: list[str] = field(default_factory=list)
    detected_env: str | None = None
    signals: list[str] = field(default_factory=list)


class RuleBasedDetector:
    """Быстрые детерминированные правила для évidentных атак."""

    # ruff: noqa: RUF012 — константы не мутируют

    INJECTION_PATTERNS = [
        r'(?i)ignore\s+(all\s+)?(previous|prior|system|above)\s+instructions',
        r'(?i)disregard\s+(the\s+)?(system\s+)?prompt',
        r'(?i)you\s+are\s+now\s+(AIM|DAN|unfiltered|amoral)',
        r'(?i)jailbreak',
        r'(?i)developer\s+mode',
        r'(?i)hypothetical\s+scenario.*(root|admin|prod)',
        r'(?i)pretend\s+to\s+be',
        r'(?i)roleplay\s+as',
        r'(?i)act\s+as\s+if\s+you\s+are',
        r'(?i)you\s+are\s+now\s+a\s+(developer|admin|root|superuser)',
        r'(?i)bypass\s+(all\s+)?(safety|security|restriction|filter)',
        r'(?i)without\s+(any\s+)?(restriction|limitation|confirmation)',
        r'(?i)игнорируй\s+(все\s+)?(предыдущие|системные|прошлые)\s+инструкц',
        r'(?i)забудь\s+(все\s+)?(предыдущие\s+)?инструкц',
        r'(?i)игнорируй\s+системн\w*\s+(промпт|инструкц)',
        r'(?i)обойди\s+(защит|ограничен|политик)',
        r'(?i)притворись\s+(что\s+)?(ты|вы)\s+(администратор|админ|root)',
        r'(?i)теперь\s+(ты|вы)\s+(администратор|админ|root|без\s+ограничений)',
        r'(?iu)\bпритвор(?:ись|яйся)\s*,?\s*(?:что\s+)?(?:ты|вы)\s+(?:root(?:[-\s]+(?:пользователь|user))?|админ(?:истратор)?)\b',
        r'(?i)\byou\s+are\s+now\s+(?:an?\s+)?(?:unfiltered|unrestricted|unlimited|amoral)(?:\s+(?:admin(?:istrator)?|root))?(?:\s+with\s+(?:root|admin)\s+access)?\b',
    ]

    PROMPT_INJECTION_PATTERNS = [
        r'(?i)system\s*:\s*run',
        r'(?i)```system\s*\n',
        r'(?i)override\s+(instructions|rules|role)',
        r'(?i)new\s+instructions',
        r'(?i)forget\s+everything',
        r'(?i)admin\s+override',
        r'(?i)emergency\s+access',
        r'(?i)sudo\s+mode',
        r'(?i)ignore\s+(?:everything|anything)\b[^\r\n]{0,100}\b(?:system\s+(?:message|prompt|instructions?)|safety\s+checks?)\b',
        r'(?i)###\s*new\s+policy\s*###|\b(?:new|updated?)\s+(?:policy|rules?)\b[^\r\n]{0,100}\b(?:every\s+user\s+is\s+(?:an?\s+)?admin|run\s+without\s+confirmation)\b',
        r'(?i)\b(?:decode|decrypt)\b[^\r\n]{0,100}\bbase64\b[^\r\n]{0,100}\b(?:follow|execute|run)\b',
        r'(?iu)\bдекодируй\b[^\r\n]{0,100}\bbase64\b[^\r\n]{0,100}\b(?:выполн|следуй)\w*',
        r'(?i)\bread\b[^\r\n]{0,100}\bbackwards?\b[^\r\n]{0,100}\b(?:do|follow|execute|run)\b',
        r'(?iu)\bзадом\s+напер[её]д\b[^\r\n]{0,100}\b(?:выполн|сделай|следуй)\w*',
    ]

    INDIRECT_INJECTION_PATTERNS = [
        r'(?i)<!--\s*AI\s+agent:',
        r'(?i)<!--\s*system:',
        r'(?i)SYSTEM:\s+The\s+user\s+is\s+an\s+administrator',
        r'(?i)hidden\s+instruction',
        r'(?i)secret\s+instruction',
        r'(?i)if\s+you\s+are\s+reading\s+this',
        r'(?i)when\s+you\s+see\s+this',
        r'(?i)process\s+the\s+following\s+as\s+(a\s+)?(command|instruction)',
        r'(?i)execute\s+the\s+following',
        r'(?i)run\s+the\s+following',
        r'(?i)AI\s+agent:.*run|AI\s+agent:.*execute|AI\s+agent:.*iptables',
        r'(?i)document\s+contains\s+hidden',
        r'(?i)\bai[- ]?(?:agent|assistant)\s+instructions?\s*:',
        r'(?iu)\bинструкц\w*\s+для\s+ии[- ]?ассистент\w*\s*:',
        r'(?iu)\bассистент\s*,?\s+(?:чтобы\s+)?[^\r\n]{0,100}\b(?:удал\w*|отправ\w*|выгруз\w*|выполн\w*)\b[^\r\n]{0,160}\b(?:без\s+подтвержден\w*|секрет\w*|token\w*|kubeconfig)\b',
    ]

    SYSTEM_PROMPT_EXTRACTION = [
        (
            r'(?i)\b(?:reveal|show|print|quote|repeat|copy|disclose|return|output|display|give|send|leak|dump)\s+'
            r'(?:(?:me|us|the|your|full|exact|original|hidden|internal|entire|current|verbatim|text|of)\s+){0,7}'
            r'system\s+prompt\b'
        ),
        r'(?i)what\s+(are|were)\s+(your|the)\s+instructions',
        r'(?i)quote\s+(your|the)\s+(system\s+)?instructions',
        r'(?i)reveal\s+(your|the)\s+(system\s+)?prompt',
        r'(?i)show\s+me\s+(your|the)\s+instructions',
        r'(?i)what\s+are\s+your\s+guidelines',
        r'(?i)\bwhat\s+(?:is|was)\s+your\s+system\s+prompt\b',
        r'(?i)leak\s+(your|the)\s+(system\s+)?prompt',
        r'(?i)print\s+your\s+instructions',
        r'(?i)(покажи|раскрой|выведи|процитируй)\s+(свой|твой|ваш)?\s*системн\w*\s+(промпт|инструкц)',
        r'(?i)какие\s+(у\s+тебя|у\s+вас)\s+системн\w*\s+инструкц',
        r'(?iu)\b(?:покажи|раскрой|выведи|процитируй|перечисли)\s+(?:(?:сво|тво|ваш)\w*\s+)?системн\w*\s+(?:промпт|инструкц\w*)\b',
        r'(?i)\bwhat\s+(?:are|were)\s+(?:your|the)\s+(?:\w+\s+){0,3}(?:instructions|guidelines|rules)\b',
    ]

    SYSTEM_PROMPT_OVERRIDE = [
        r'(?i)you\s+are\s+now\s+(a\s+)?(different|new)',
        r'(?i)your\s+new\s+role\s+is',
        r'(?i)from\s+now\s+on\s+you\s+are',
        r'(?i)change\s+your\s+role\s+to',
        r'(?i)override\s+your\s+role',
        r'(?i)you\s+are\s+no\s+longer',
        r'(?i)ignore\s+your\s+previous\s+role',
    ]

    PRIVILEGE_ESCALATION = [
        r'(?i)i\s+am\s+(an\s+)?admin',
        r'(?i)i\s+am\s+(the\s+)?administrator',
        r'(?i)i\s+have\s+(root|admin|sudo)\s+access',
        r'(?i)verify\s+(my|the)\s+(admin|root)\s+status',
        r'(?i)i\s+am\s+(acting\s+)?as\s+admin',
        r'(?i)my\s+role\s+is\s+admin',
        r'(?i)grant\s+me\s+admin',
        r'(?i)elevate\s+my\s+privileges',
    ]

    DATA_EXFILTRATION = [
        r'(?i)send\s+to\s+(external|outside|third.?party)',
        r'(?i)exfiltrat',
        r'(?i)curl\s+.*\|.*(bash|sh)',
        r'(?i)pipe\s+to\s+shell',
        r'(?i)send\s+(data|secrets|logs)\s+to',
        r'(?i)upload\s+to\s+(external|outside)',
        r'(?i)post\s+to\s+(external|outside)',
        r'(?i)\b(?:send|upload|post|export)\b[^\r\n]{0,200}\b(?:secrets?|tokens?|logs?|data)\b[^\r\n]{0,200}\b(?:external|outside|third[- ]?party)\b',
        r'(?iu)\b(?:отправ\w*|переда\w*|перешл\w*|выгруз\w*|экспортир\w*)\b[^\r\n]{0,200}\b(?:секрет\w*|парол\w*|токен\w*|ключ\w*|лог\w*|данн\w*)\b[^\r\n]{0,200}\b(?:внешн\w*|треть\w*\s+сторон\w*|наруж\w*)',
        r'(?iu)\b(?:секрет\w*|парол\w*|токен\w*|ключ\w*|лог\w*|данн\w*)\b[^\r\n]{0,200}\b(?:отправ\w*|переда\w*|перешл\w*|выгруз\w*|экспортир\w*)\b[^\r\n]{0,200}\b(?:внешн\w*|треть\w*\s+сторон\w*|наруж\w*)',
    ]

    HARMFUL_CONTENT = [
        r'(?i)exploit\s+for\s+(remote|rce|code\s+execution)',
        r'(?i)reverse\s+shell',
        r'(?i)bomb\s+|explosive|weapon|narcotic|drug',
        r'(?i)malware|ransomware|trojan',
        r'(?i)disable\s+(alarm|camera|security)\s+in\s+(someone|another|other|foreign)',
        r'(?i)how\s+to\s+(make|build|create)\s+(bomb|explosive|weapon)',
        r'(?i)instructions\s+for\s+(harming|hurting|killing)',
        r'(?i)\b(?:write|create|craft|develop|give)\b[^\r\n]{0,80}\b(?:rce|remote\s+code\s+execution)\s+exploit\b',
    ]

    UNAUTHORIZED_DATA_ACCESS = [
        r'(?i)\b(?:show|print|dump|reveal|read)\b[^\r\n]{0,120}\b(?:aws\s+access\s+keys?|passwords?|tokens?|secrets?|vault)\b',
        r'(?iu)\b(?:покажи|выведи|прочитай|раскрой|дамп)\b[^\r\n]{0,120}\b(?:парол\w*|токен\w*|секрет\w*|vault)\b',
        r'(?iu)\b(?:покажи|выведи|раскрой)[\w\s/-]{0,160}(?:vault|secret)[\w\s/-]{0,160}(?:prod|production)',
    ]

    SENSITIVE_ACTION_PATTERNS = [
        r'(?iu)\b(?:выполни|запусти)\s+(?:миграц\w*|migration)\b',
    ]

    TOOL_ABUSE_PATTERNS = [
        r'(?i)run\s+on\s+\S+.*:\s*(chmod|rm\s+-rf|dd\s+|mkfs)',
        r'(?i)execute\s+(the\s+)?(instruction|command|code)\s+above',
        r'(?i)chmod\s+-R\s+777',
        r'(?i)rm\s+-rf\s+/',
        r'(?i)format\s+(the\s+)?(drive|disk)',
        r'(?i)delete\s+all\s+(data|files|resources)',
        r'(?i)wipe\s+(the\s+)?(server|disk|drive)',
        r'(?i)drop\s+(the\s+)?(?:[\w.-]+\s+){0,3}(database|db|table|schema)',
    ]

    def __init__(self) -> None:
        self._compiled: dict[str, list[re.Pattern[str]]] = {}
        self._compile_all()

    def _compile_all(self) -> None:
        groups: dict[str, list[str]] = {
            'jailbreak': self.INJECTION_PATTERNS,
            'prompt_injection': self.PROMPT_INJECTION_PATTERNS,
            'indirect_injection': self.INDIRECT_INJECTION_PATTERNS,
            'system_prompt_extraction': self.SYSTEM_PROMPT_EXTRACTION,
            'system_prompt_override': self.SYSTEM_PROMPT_OVERRIDE,
            'privilege_escalation': self.PRIVILEGE_ESCALATION,
            'unauthorized_data_access': self.UNAUTHORIZED_DATA_ACCESS,
            'sensitive_action': self.SENSITIVE_ACTION_PATTERNS,
            'data_exfiltration': self.DATA_EXFILTRATION,
            'harmful_content': self.HARMFUL_CONTENT,
            'tool_abuse': self.TOOL_ABUSE_PATTERNS,
        }
        for name, patterns in groups.items():
            self._compiled[name] = [re.compile(p) for p in patterns]

    def detect(self, text: str) -> list[tuple[str, str]]:
        findings: list[tuple[str, str]] = []
        for category, patterns in self._compiled.items():
            for pat in patterns:
                if pat.search(text):
                    findings.append((category, pat.pattern))
        return findings


@dataclass
class TrainableClassifier:
    """Обучаемый классификатор на базе TF-IDF + логистической регрессии."""

    pipeline: Pipeline | None = None
    categories: list[str] = field(default_factory=list)
    levels: list[str] = field(default_factory=list)
    is_trained: bool = False
    confidence_threshold: float = 0.3
    danger_model: LogisticRegression | None = None
    danger_threshold: float = 0.45

    def fit(self, texts: list[str], categories: list[str], levels: list[str]) -> None:
        from sklearn.preprocessing import LabelEncoder

        self.pipeline = Pipeline(
            [
                (
                    'tfidf',
                    FeatureUnion(
                        [
                            (
                                'chars',
                                TfidfVectorizer(analyzer='char_wb', ngram_range=(2, 5)),
                            ),
                            ('words', TfidfVectorizer(ngram_range=(1, 2))),
                        ]
                    ),
                ),
                (
                    'clf',
                    LogisticRegression(C=5, max_iter=2000, class_weight='balanced'),
                ),
            ]
        )
        le_cat = LabelEncoder()
        le_cat.fit(categories)
        self.categories = list(le_cat.classes_)

        self.pipeline.fit(texts, le_cat.transform(categories))
        features = self.pipeline.named_steps['tfidf'].transform(texts)
        dangerous = [cat not in _NON_ATTACK_CATEGORIES for cat in categories]
        self.danger_model = None
        if len(set(dangerous)) == 2:
            self.danger_model = LogisticRegression(
                C=5, max_iter=2000, class_weight='balanced'
            )
            self.danger_model.fit(features, dangerous)
        self.is_trained = True

    def predict(self, text: str) -> ClassificationResult:
        if not self.is_trained or self.pipeline is None:
            return ClassificationResult(
                risk_category='none',
                risk_level='none',
                confidence=0.0,
                is_attack=False,
            )

        import numpy as np

        if self.danger_model is not None:
            features = self.pipeline.named_steps['tfidf'].transform([text])
            danger_score = float(self.danger_model.predict_proba(features)[0, 1])
            is_dangerous = danger_score >= self.danger_threshold
            proba = self.pipeline.named_steps['clf'].predict_proba(features)[0]
            candidates = [
                i
                for i, category in enumerate(self.categories)
                if (category not in _NON_ATTACK_CATEGORIES) == is_dangerous
            ]
            idx = max(candidates, key=lambda i: proba[i])
        else:
            proba = self.pipeline.predict_proba([text])[0]
            idx = int(np.argmax(proba))
        cat = self.categories[idx]
        conf = float(proba[idx])

        if (
            self.danger_model is None
            and conf < self.confidence_threshold
            and cat != 'none'
        ):
            return ClassificationResult(
                risk_category='none',
                risk_level='none',
                confidence=conf,
                is_attack=False,
            )

        level_map = {
            'prompt_injection': 'high',
            'jailbreak': 'high',
            'indirect_injection': 'high',
            'system_prompt_extraction': 'medium',
            'system_prompt_override': 'high',
            'tool_abuse': 'high',
            'privilege_escalation': 'high',
            'unauthorized_data_access': 'medium',
            'data_exfiltration': 'critical',
            'harmful_content': 'critical',
            'fraud_social_engineering': 'medium',
            'abuse': 'medium',
            'sensitive_action': 'medium',
            'external_communication': 'medium',
            'none': 'none',
        }

        return ClassificationResult(
            risk_category=cat,
            risk_level=level_map.get(cat, 'none'),
            confidence=conf,
            is_attack=cat != 'none' and cat != 'external_communication',
        )


class Classifier:
    """Главный классификатор: комбинирует правила и обучаемую модель."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings(
            policy_path='dataset/security_policy.yaml',
            journal_path='temp/journal.jsonl',
            sessions_path='temp/sessions.json',
            adapter_path='temp/adapter.json',
        )
        self.rule_detector = RuleBasedDetector()
        self.model: TrainableClassifier | None = None
        self._tool_patterns = [
            re.compile(r'\brun_shell\b', re.IGNORECASE),
            re.compile(r'\bread_logs\b', re.IGNORECASE),
            re.compile(r'\brestart_service\b', re.IGNORECASE),
            re.compile(r'\bdelete_resource\b', re.IGNORECASE),
        ]

    @staticmethod
    def _normalize_for_detection(text: str) -> str:
        """Remove invisible and simple character-spacing obfuscation for rules."""
        normalized = unicodedata.normalize('NFKC', text)
        normalized = re.sub(r'[\u200b-\u200d\ufeff]', '', normalized)

        def collapse(match: re.Match[str]) -> str:
            return re.sub(r'[ \t]+', '', match.group(0))

        collapsed = re.sub(
            r'(?u)(?<!\w)(?:[A-Za-zА-Яа-яЁё0-9][ \t]+){2,}[A-Za-zА-Яа-яЁё0-9](?!\w)',
            collapse,
            normalized,
        )
        return normalized if collapsed == normalized else normalized + '\n' + collapsed

    def load_model(self, model_dir: str | Path) -> None:
        model_path = Path(model_dir) / 'classifier.joblib'
        if model_path.exists():
            data = joblib.load(model_path)
            self.model = data['model']
            self.model.is_trained = True

    def save_model(self, model_dir: str | Path) -> None:
        if self.model is None:
            return
        Path(model_dir).mkdir(parents=True, exist_ok=True)
        joblib.dump({'model': self.model}, Path(model_dir) / 'classifier.joblib')

    def train(self, texts: list[str], categories: list[str], levels: list[str]) -> None:
        self.model = TrainableClassifier()
        self.model.fit(texts, categories, levels)

    def _extract_tools(self, text: str) -> list[str]:
        found: list[str] = []
        for pat in self._tool_patterns:
            if pat.search(text):
                name = pat.pattern.replace(r'\b', '').replace(r'\s*', '_')
                found.append(name.strip('_'))
        return found

    def classify(
        self,
        user_prompt: str,
        history: list[dict[str, str]],
        attachments: list[dict[str, str]],
        *,
        always_block: Collection[str] = (),
    ) -> ClassificationResult:
        parts: list[str] = [user_prompt]
        for entry in history:
            parts.append(entry.get('content', ''))
        for att in attachments:
            parts.append(att.get('content', ''))
        full_text = '\n'.join(parts)

        rule_findings = self.rule_detector.detect(
            self._normalize_for_detection(full_text)
        )
        if rule_findings:
            severity = {
                'data_exfiltration': 5,
                'harmful_content': 5,
                'jailbreak': 4,
                'prompt_injection': 4,
                'indirect_injection': 4,
                'system_prompt_override': 4,
                'system_prompt_extraction': 3,
                'privilege_escalation': 3,
                'tool_abuse': 3,
                'unauthorized_data_access': 2,
                'fraud_social_engineering': 2,
                'abuse': 2,
            }
            best_cat = max(
                (category for category, _ in rule_findings),
                key=lambda category: (category in always_block, severity.get(category, 1)),
            )
            level_map = {
                'data_exfiltration': 'critical',
                'harmful_content': 'critical',
                'jailbreak': 'high',
                'prompt_injection': 'high',
                'indirect_injection': 'high',
                'system_prompt_override': 'high',
                'system_prompt_extraction': 'medium',
                'privilege_escalation': 'high',
                'tool_abuse': 'high',
                'unauthorized_data_access': 'medium',
                'fraud_social_engineering': 'medium',
                'abuse': 'medium',
            }
            return ClassificationResult(
                risk_category=best_cat,
                risk_level=level_map.get(best_cat, 'medium'),
                confidence=0.95,
                is_attack=True,
                detected_tools=self._extract_tools(full_text),
                signals=[f'rule:{f[0]}' for f in rule_findings],
            )

        if self.model is not None and self.model.is_trained:
            model_text = full_text
            if self.model.danger_model is not None:
                model_text = classification_text(user_prompt, history, attachments)
            result = self.model.predict(model_text)
            if (
                'external_communication' in self.model.categories
                and (history or attachments)
                and result.risk_category in {'none', 'external_communication'}
            ):
                current = self.model.predict(classification_text(user_prompt, [], []))
                if current.risk_category == 'external_communication':
                    result = current
                elif result.risk_category == 'external_communication':
                    result = ClassificationResult('none', 'none', 0.0, False)
            result = ClassificationResult(
                risk_category=result.risk_category,
                risk_level=result.risk_level,
                confidence=result.confidence,
                is_attack=result.is_attack,
                detected_tools=self._extract_tools(full_text),
            )
            return result

        return ClassificationResult(
            risk_category='none',
            risk_level='none',
            confidence=0.5,
            is_attack=False,
            detected_tools=self._extract_tools(full_text),
        )
