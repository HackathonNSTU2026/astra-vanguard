from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from src.config.settings import Settings


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
    ]

    SYSTEM_PROMPT_EXTRACTION = [
        r'(?i)system\s+prompt',
        r'(?i)what\s+(are|were)\s+(your|the)\s+instructions',
        r'(?i)quote\s+(your|the)\s+(system\s+)?instructions',
        r'(?i)reveal\s+(your|the)\s+(system\s+)?prompt',
        r'(?i)show\s+me\s+(your|the)\s+instructions',
        r'(?i)what\s+are\s+your\s+guidelines',
        r'(?i)your\s+system\s+prompt',
        r'(?i)leak\s+(your|the)\s+(system\s+)?prompt',
        r'(?i)print\s+your\s+instructions',
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
    ]

    HARMFUL_CONTENT = [
        r'(?i)exploit\s+for\s+(remote|rce|code\s+execution)',
        r'(?i)reverse\s+shell',
        r'(?i)bomb\s+|explosive|weapon|narcotic|drug',
        r'(?i)malware|ransomware|trojan',
        r'(?i)disable\s+(alarm|camera|security)\s+in\s+(someone|another|other|foreign)',
        r'(?i)how\s+to\s+(make|build|create)\s+(bomb|explosive|weapon)',
        r'(?i)instructions\s+for\s+(harming|hurting|killing)',
    ]

    TOOL_ABUSE_PATTERNS = [
        r'(?i)run\s+on\s+\S+.*:\s*(chmod|rm\s+-rf|dd\s+|mkfs)',
        r'(?i)execute\s+(the\s+)?(instruction|command|code)\s+above',
        r'(?i)chmod\s+-R\s+777',
        r'(?i)rm\s+-rf\s+/',
        r'(?i)format\s+(the\s+)?(drive|disk)',
        r'(?i)drop\s+(the\s+)?(database|table)',
        r'(?i)delete\s+all\s+(data|files|resources)',
        r'(?i)wipe\s+(the\s+)?(server|disk|drive)',
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

    def fit(self, texts: list[str], categories: list[str], levels: list[str]) -> None:
        from sklearn.preprocessing import LabelEncoder

        self.pipeline = Pipeline(
            [
                (
                    'tfidf',
                    TfidfVectorizer(
                        ngram_range=(1, 3),
                        analyzer='char_wb',
                        min_df=1,
                        max_features=5000,
                    ),
                ),
                ('clf', LogisticRegression(max_iter=2000, class_weight='balanced')),
            ]
        )
        le_cat = LabelEncoder()
        le_cat.fit(categories)
        self.categories = list(le_cat.classes_)

        self.pipeline.fit(texts, le_cat.transform(categories))
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

        proba = self.pipeline.predict_proba([text])[0]
        idx = int(np.argmax(proba))
        cat = self.categories[idx]
        conf = float(proba[idx])

        if conf < self.confidence_threshold and cat != 'none':
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
            'none': 'none',
        }

        return ClassificationResult(
            risk_category=cat,
            risk_level=level_map.get(cat, 'none'),
            confidence=conf,
            is_attack=cat != 'none',
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
    ) -> ClassificationResult:
        parts: list[str] = [user_prompt]
        for entry in history:
            parts.append(entry.get('content', ''))
        for att in attachments:
            parts.append(att.get('content', ''))
        full_text = '\n'.join(parts)

        rule_findings = self.rule_detector.detect(full_text)
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
            best_cat = max(rule_findings, key=lambda x: severity.get(x[0], 1))[0]
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
            result = self.model.predict(full_text)
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
