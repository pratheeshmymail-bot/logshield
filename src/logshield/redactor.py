"""Offline redaction of common secrets and personal data in text logs."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Pattern


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: Pattern[str]
    replacement: str = "[REDACTED]"


# Keep patterns specific enough to avoid masking ordinary words unnecessarily.
RULES: tuple[Rule, ...] = (
    Rule("openai_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    Rule("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    Rule("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    Rule("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    Rule("bearer_token", re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]{12,}"), "[REDACTED_BEARER_TOKEN]"),
    Rule("password_assignment", re.compile(
        r"""(?i)\b(password|passwd|pwd|client_secret|api[_-]?secret)\s*([=:]\s*)["']?([^\s"',;]+)"""
    ), None),
    Rule("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
)


def redact_text(text: str, rules: Iterable[Rule] = RULES) -> tuple[str, dict[str, int]]:
    """Return redacted text and per-rule replacement counts."""
    counts: dict[str, int] = {}
    result = text

    for rule in rules:
        if rule.name == "password_assignment":
            def replace_assignment(match: re.Match[str]) -> str:
                return f"{match.group(1)}{match.group(2)}[REDACTED]"
            result, count = rule.pattern.subn(replace_assignment, result)
        elif rule.name == "bearer_token":
            result, count = rule.pattern.subn(lambda m: m.group(1) + "[REDACTED_BEARER_TOKEN]", result)
        else:
            result, count = rule.pattern.subn(rule.replacement, result)

        if count:
            counts[rule.name] = count

    return result, counts
