import json
import pytest
from logshield.redactor import redact_json_text, redact_text


def test_redacts_email():
    cleaned, counts = redact_text("contact alice@example.com")
    assert "alice@example.com" not in cleaned
    assert counts["email"] == 1


def test_redacts_password_assignment():
    cleaned, counts = redact_text("password=hunter2")
    assert cleaned == "password=[REDACTED]"
    assert counts["password_assignment"] == 1


def test_redacts_bearer_token():
    cleaned, counts = redact_text("Authorization: Bearer abcdefghijklmnop123")
    assert "abcdefghijklmnop123" not in cleaned
    assert counts["bearer_token"] == 1


def test_leaves_normal_text_alone():
    original = "The service started successfully on port 8080."
    assert redact_text(original) == (original, {})


def test_redacts_openai_style_key():
    secret = "sk-" + "A" * 25
    cleaned, counts = redact_text(f"key={secret}")
    assert secret not in cleaned
    assert counts["openai_api_key"] == 1


def test_json_sensitive_keys_are_redacted_and_structure_preserved():
    original = {"service": "billing", "credentials": {"password": "hunter2", "api_key": "example-key"},
                "items": [{"email": "alice@example.com"}], "enabled": True, "retries": 3}
    cleaned, counts = redact_json_text(json.dumps(original))
    parsed = json.loads(cleaned)
    assert parsed["credentials"]["password"] == "[REDACTED]"
    assert parsed["credentials"]["api_key"] == "[REDACTED]"
    assert parsed["items"][0]["email"] == "[REDACTED]"
    assert parsed["enabled"] is True and parsed["retries"] == 3
    assert counts["sensitive_json_key"] == 2 and counts["email"] == 1


def test_json_redacts_secret_patterns_inside_values():
    cleaned, counts = redact_json_text(json.dumps({"message": "Authorization: Bearer abcdefghijklmnop123"}))
    assert "abcdefghijklmnop123" not in cleaned
    assert counts["bearer_token"] == 1


def test_invalid_json_raises_value_error():
    with pytest.raises(json.JSONDecodeError):
        redact_json_text("{not valid json")
