from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.classifier import Classifier
from src.config.settings import Settings
from src.decision import DecisionMaker
from src.explain import Explainer
from src.journal import Journal
from src.policy.loader import load_policy


@dataclass
class CheckRequest:
    user_prompt: str
    context: dict[str, Any]


@dataclass
class CheckResponse:
    decision: str
    risk_level: str
    risk_category: str
    explanation: str
    latency_ms: float


class Guard:
    """ИИ-сторож: основной конвейер проверки входящих запросов."""

    def __init__(
        self, settings: Settings | None = None, model_dir: str | Path | None = None
    ) -> None:
        self.settings = settings or Settings(
            policy_path='dataset/security_policy.yaml',
            journal_path='data/journal.jsonl',
            sessions_path='data/sessions.json',
            adapter_path='data/adapter.json',
        )
        self.policy = load_policy(self.settings.policy_path)
        self.classifier = Classifier(settings=self.settings)
        if model_dir:
            self.classifier.load_model(model_dir)
            if self.classifier.model is not None:
                self.classifier.model.confidence_threshold = 0.15
        self.decision_maker = DecisionMaker(self.policy, self.classifier)
        self.explainer = Explainer()
        self.journal = Journal(
            self.settings.journal_path, policy_version=self.policy.version
        )

    def check(
        self,
        user_prompt: str,
        context: dict[str, Any],
    ) -> CheckResponse:
        start = time.perf_counter()

        user_role = context.get('user_role', 'developer')
        user_id = context.get('user_id')
        history = context.get('history', [])
        attachments = context.get('attachments', [])
        target_agent = context.get('target_agent', 'it_ops_agent')

        maker = self.decision_maker
        classification = self.classifier.classify(
            user_prompt, history, attachments, always_block=maker.policy.always_block
        )

        from src.policy.environments import detect_environment

        # Authorization scope comes from the current requested operation only.
        # Old messages and attachments are untrusted data, not environment claims.
        env = detect_environment(user_prompt)

        decision = maker.make(
            classification=classification,
            user_role=user_role,
            user_prompt=user_prompt,
            history=history,
            attachments=attachments,
            target_agent=target_agent,
        )

        explanation = self.explainer.explain(decision, user_role=user_role, env=env)

        latency_ms = (time.perf_counter() - start) * 1000

        self.journal.add(
            user_role=user_role,
            user_id=user_id,
            decision=decision.decision,
            risk_category=decision.risk_category,
            risk_level=decision.risk_level,
            latency_ms=latency_ms,
            user_prompt=user_prompt,
            explanation=explanation,
        )

        return CheckResponse(
            decision=decision.decision,
            risk_level=decision.risk_level,
            risk_category=decision.risk_category,
            explanation=explanation,
            latency_ms=round(latency_ms, 3),
        )

    def reload_policy(self) -> None:
        self.policy = load_policy(self.settings.policy_path)
        self.decision_maker = DecisionMaker(self.policy, self.classifier)
        self.journal.policy_version = self.policy.version
