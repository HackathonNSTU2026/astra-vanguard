from __future__ import annotations

from pathlib import Path

import yaml

from src.policy.models import AgentPolicy, RolePolicy, SecurityPolicy


def load_policy(path: str | Path) -> SecurityPolicy:
    """Загружает политику безопасности из YAML-файла.

    Никакие права не жёстко зашиты в коде — все правила читаются из файла.
    """
    with open(path, 'r', encoding='utf-8') as f:
        raw = yaml.safe_load(f)

    agents: dict[str, AgentPolicy] = {}
    for name, data in (raw.get('agents') or {}).items():
        roles: dict[str, RolePolicy] = {}
        for role_name, role_data in (data.get('roles') or {}).items():
            roles[role_name] = RolePolicy(
                tools=role_data.get('tools', {}),
                secrets=role_data.get('secrets', 'deny'),
            )
        agents[name] = AgentPolicy(
            tools=list(data.get('tools', [])),
            environments=data.get('environments', {}),
            roles=roles,
            forbidden_actions=list(data.get('forbidden_actions', [])),
        )

    return SecurityPolicy(
        version=int(raw.get('version', 1)),
        decisions=dict(raw.get('decisions', {})),
        always_block=list(raw.get('always_block', [])),
        context_dependent=list(raw.get('context_dependent', [])),
        agents=agents,
        forbidden_actions=list(raw.get('forbidden_actions', [])),
    )


def reload_policy(path: str | Path) -> SecurityPolicy:
    """Перезагружает политику с диска (используется жюри при изменении YAML)."""
    return load_policy(path)
