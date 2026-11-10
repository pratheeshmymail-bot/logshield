import json
import pytest
from logshield.redactor import redact_json_text, redact_text, load_custom_rules

def test_redacts_email():
    cleaned, counts=redact_text("contact alice@example.com")
    assert "alice@example.com" not in cleaned and counts["email"]==1

def test_redacts_password_assignment():
    cleaned,counts=redact_text("password=hunter2")
    assert cleaned=="password=[REDACTED]" and counts["password_assignment"]==1

def test_redacts_bearer_token():
    cleaned,counts=redact_text("Authorization: Bearer abcdefghijklmnop123")
    assert "abcdefghijklmnop123" not in cleaned and counts["bearer_token"]==1

def test_leaves_normal_text_alone():
    original="The service started successfully on port 8080."
    assert redact_text(original)==(original,{})

def test_redacts_openai_style_key():
    secret="sk-"+"A"*25
    cleaned,counts=redact_text(f"key={secret}")
    assert secret not in cleaned and counts["openai_api_key"]==1

def test_json_structure_preserved():
    original={"service":"billing","credentials":{"password":"hunter2","api_key":"example-key"},"items":[{"email":"alice@example.com"}],"enabled":True,"retries":3}
    cleaned,counts=redact_json_text(json.dumps(original)); parsed=json.loads(cleaned)
    assert parsed["credentials"]["password"]=="[REDACTED]"
    assert parsed["credentials"]["api_key"]=="[REDACTED]"
    assert parsed["items"][0]["email"]=="[REDACTED]"
    assert parsed["enabled"] is True and parsed["retries"]==3
    assert counts["sensitive_json_key"]==2 and counts["email"]==1

def test_invalid_json_raises():
    with pytest.raises(json.JSONDecodeError): redact_json_text("{not valid json")

def test_jwt_detected_but_plain_dotted_text_not():
    token="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.signaturepayload123"
    cleaned,counts=redact_text("jwt="+token)
    assert token not in cleaned and counts["jwt"]==1
    ordinary="release.version.number"
    assert redact_text(ordinary)==(ordinary,{})

def test_database_url_password_masked_and_username_kept():
    cleaned,counts=redact_text("postgresql://appuser:s3cretPass@db.example.test:5432/app")
    assert "s3cretPass" not in cleaned
    assert "appuser:[REDACTED]@db.example.test" in cleaned
    assert counts["database_url_password"]==1

def test_google_api_key_detected():
    key="AIza"+"A"*35
    cleaned,counts=redact_text("key="+key)
    assert key not in cleaned and counts["google_api_key"]==1

def test_pem_private_key_block_detected():
    sample="-----BEGIN PRIVATE KEY-----\nSYNTHETIC_PRIVATE_MATERIAL\n-----END PRIVATE KEY-----"
    cleaned,counts=redact_text(sample)
    assert "SYNTHETIC_PRIVATE_MATERIAL" not in cleaned
    assert counts["pem_private_key"]==1

def test_custom_rules_loaded(tmp_path):
    rules_file=tmp_path/"rules.json"
    rules_file.write_text(json.dumps([{"name":"employee_id","pattern":r"EMP-[0-9]{5}"}]))
    custom=load_custom_rules(rules_file)
    cleaned,counts=redact_text("employee EMP-12345", custom)
    assert "EMP-12345" not in cleaned and counts["custom_employee_id"]==1

def test_invalid_custom_regex_rejected(tmp_path):
    rules_file=tmp_path/"rules.json"
    rules_file.write_text(json.dumps([{"name":"bad","pattern":"["}]))
    with pytest.raises(ValueError): load_custom_rules(rules_file)

def test_custom_rules_must_be_json_array(tmp_path):
    rules_file=tmp_path/"rules.json"; rules_file.write_text("{}")
    with pytest.raises(ValueError): load_custom_rules(rules_file)
