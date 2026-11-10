from logshield.redactor import redact_text


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
    cleaned, counts = redact_text(original)
    assert cleaned == original
    assert counts == {}


def test_redacts_openai_style_key():
    secret = "sk-" + "A" * 25
    cleaned, counts = redact_text(f"key={secret}")
    assert secret not in cleaned
    assert counts["openai_api_key"] == 1
