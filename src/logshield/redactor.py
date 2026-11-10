"""Offline redaction of common secrets and personal data in text and JSON."""
from __future__ import annotations
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Pattern

@dataclass(frozen=True)
class Rule:
    name: str
    pattern: Pattern[str]
    replacement: str = "[REDACTED]"

# Patterns are heuristic. Review output; no scanner can recognize every secret.
RULES: tuple[Rule, ...] = (
    Rule("openai_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    Rule("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    Rule("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    Rule("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    Rule("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    Rule("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    Rule("database_url_password", re.compile(r"(?i)\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss)://[^:/@\s]+:)([^@/\s]+)(@)"), None),
    Rule("pem_private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    Rule("bearer_token", re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]{12,}"), "[REDACTED_BEARER_TOKEN]"),
    Rule("password_assignment", re.compile(r"(?i)\b(password|passwd|pwd|client_secret|api[_-]?secret)\s*([=:]\s*)[\"']?([^\s\"',;]+)"), None),
    Rule("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
)

SENSITIVE_JSON_KEYS = {
    "password", "passwd", "pwd", "secret", "client_secret", "api_secret",
    "api_key", "apikey", "access_token", "refresh_token", "auth_token",
    "token", "authorization", "private_key", "secret_key", "credentials",
}

def load_custom_rules(path: str | Path | None) -> tuple[Rule, ...]:
    """Load optional JSON rules: [{"name":"...", "pattern":"...", "replacement":"..."}]."""
    if path is None:
        return ()
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("Custom rules file must contain a JSON array")
    rules: list[Rule] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("pattern"), str):
            raise ValueError(f"Custom rule {index} must contain string 'name' and 'pattern' fields")
        name = item["name"].strip()
        if not name or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
            raise ValueError(f"Custom rule {index} has an invalid name")
        replacement = item.get("replacement", "[REDACTED]")
        if not isinstance(replacement, str):
            raise ValueError(f"Custom rule {index} replacement must be a string")
        try:
            pattern = re.compile(item["pattern"])
        except re.error as exc:
            raise ValueError(f"Custom rule {name!r} has an invalid regex: {exc}") from exc
        rules.append(Rule("custom_" + name, pattern, replacement))
    return tuple(rules)

def redact_text(text: str, rules: Iterable[Rule] = RULES) -> tuple[str, dict[str, int]]:
    """Return redacted text and per-rule replacement counts."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    counts: dict[str, int] = {}
    result = text
    for rule in rules:
        if rule.name == "password_assignment":
            def replace_assignment(match: re.Match[str]) -> str:
                return f"{match.group(1)}{match.group(2)}[REDACTED]"
            result, count = rule.pattern.subn(replace_assignment, result)
        elif rule.name == "database_url_password":
            result, count = rule.pattern.subn(lambda m: m.group(1) + "[REDACTED]" + m.group(3), result)
        elif rule.name == "bearer_token":
            result, count = rule.pattern.subn(lambda m: m.group(1) + "[REDACTED_BEARER_TOKEN]", result)
        else:
            result, count = rule.pattern.subn(rule.replacement or "[REDACTED]", result)
        if count:
            counts[rule.name] = counts.get(rule.name, 0) + count
    return result, counts

def redact_json_text(text: str, custom_rules: Iterable[Rule] = ()) -> tuple[str, dict[str, int]]:
    """Redact sensitive JSON values while preserving JSON structure and types."""
    parsed = json.loads(text)
    counts: dict[str, int] = {}
    def add(found: dict[str, int]) -> None:
        for name, count in found.items():
            counts[name] = counts.get(name, 0) + count
    def walk(value: Any, parent_key: str | None = None) -> Any:
        if isinstance(value, dict):
            return {key: walk(child, key) for key, child in value.items()}
        if isinstance(value, list):
            return [walk(child, parent_key) for child in value]
        if isinstance(value, str):
            if parent_key and parent_key.lower() in SENSITIVE_JSON_KEYS:
                counts["sensitive_json_key"] = counts.get("sensitive_json_key", 0) + 1
                return "[REDACTED]"
            cleaned, found = redact_text(value, (*RULES, *custom_rules))
            add(found)
            return cleaned
        return value
    return json.dumps(walk(parsed), ensure_ascii=False, indent=2), counts
