from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ToolRule:
    value: str  # "allow", "deny", "confirm", "any", "nonprod"
    condition: dict[str, Any] | None = None


@dataclass(frozen=True)
class RolePolicy:
    tools: dict[str, str | dict[str, str]]
    secrets: str  # "deny", "names_only"


@dataclass(frozen=True)
class AgentPolicy:
    tools: list[str]
    environments: dict[str, list[str]]
    roles: dict[str, RolePolicy]
    forbidden_actions: list[str]


@dataclass(frozen=True)
class SecurityPolicy:
    version: int
    decisions: dict[str, str]
    always_block: list[str]
    context_dependent: list[str]
    agents: dict[str, AgentPolicy]
    forbidden_actions: list[str]

    def agent(self, name: str) -> AgentPolicy | None:
        return self.agents.get(name)
