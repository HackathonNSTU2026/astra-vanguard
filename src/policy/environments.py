from __future__ import annotations

import re

_PROD_PATTERNS = [
    re.compile(r'\bprod\b', re.IGNORECASE),
    re.compile(r'\bproduction\b', re.IGNORECASE),
]
_NONPROD_PATTERNS = [
    re.compile(r'\bdev\b', re.IGNORECASE),
    re.compile(r'\bstage\b', re.IGNORECASE),
    re.compile(r'\btest\b', re.IGNORECASE),
]


def detect_environment(text: str) -> str | None:
    """Определяет окружение по тексту.

    Возвращает "prod", "nonprod" или None (неоднозначно / не указано).
    Если есть оба — неоднозначность, возвращаем None.
    """
    has_prod = any(p.search(text) for p in _PROD_PATTERNS)
    has_nonprod = any(p.search(text) for p in _NONPROD_PATTERNS)

    if has_prod and has_nonprod:
        return None
    if has_prod:
        return 'prod'
    if has_nonprod:
        return 'nonprod'
    return None


def resource_matches_env(resource: str, env_patterns: list[str]) -> bool:
    """Проверяет, подходит ли имя ресурса под паттерны окружения."""
    import fnmatch

    return any(fnmatch.fnmatch(resource, pat) for pat in env_patterns)
