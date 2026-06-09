"""Tests for dscan.redactor.

Each category covers both cases that SHOULD be redacted and cases that
SHOULD NOT, so the redactor is pinned from both sides.
"""

import pytest

from dscan.redactor import redact

# A realistic JWT (the canonical jwt.io example), >100 chars, three parts.
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


# --------------------------------------------------------------------------
# AWS keys
# --------------------------------------------------------------------------
class TestAwsKey:
    def test_redacts_aws_access_key(self):
        assert redact("AKIAIOSFODNN7EXAMPLE") == "[REDACTED:AWS_KEY]"

    def test_redacts_aws_key_in_sentence(self):
        out = redact("key is AKIAIOSFODNN7EXAMPLE here")
        assert out == "key is [REDACTED:AWS_KEY] here"

    def test_does_not_redact_plain_uppercase_word(self):
        assert redact("AKIA") == "AKIA"
        assert redact("BANANAREPUBLICSTORE") == "BANANAREPUBLICSTORE"


# --------------------------------------------------------------------------
# API keys (Anthropic / OpenAI / GitHub / Stripe / Supabase JWT)
# --------------------------------------------------------------------------
class TestApiKeys:
    @pytest.mark.parametrize(
        "secret",
        [
            "sk-ant-api03-abc123",
            "sk-proj-abc123xyz",
            "ghp_abc123xyz456",
            "sk_live_abc123",
            JWT,
        ],
    )
    def test_redacts_api_keys(self, secret):
        assert redact(secret) == "[REDACTED:API_KEY]"

    def test_redacts_api_key_in_context(self):
        out = redact("export TOKEN=ghp_abc123xyz456")
        assert out == "export TOKEN=[REDACTED:API_KEY]"

    def test_does_not_redact_lookalikes(self):
        # "sk" without the key shape, and a short jwt-ish fragment.
        assert redact("sk") == "sk"
        assert redact("eyJ") == "eyJ"
        assert redact("the stock market") == "the stock market"


# --------------------------------------------------------------------------
# Email
# --------------------------------------------------------------------------
class TestEmail:
    def test_redacts_email(self):
        assert redact("user@example.com") == "[REDACTED:EMAIL]"

    def test_redacts_email_in_sentence(self):
        out = redact("write to user@example.com today")
        assert out == "write to [REDACTED:EMAIL] today"

    def test_does_not_redact_non_emails(self):
        assert redact("user at example dot com") == "user at example dot com"
        assert redact("@mentions are not emails") == "@mentions are not emails"


# --------------------------------------------------------------------------
# Phone numbers
# --------------------------------------------------------------------------
class TestPhone:
    def test_redacts_us_phone_with_country_code(self):
        assert redact("+1-555-867-5309") == "[REDACTED:PHONE]"

    def test_redacts_plain_phone(self):
        assert redact("555-867-5309") == "[REDACTED:PHONE]"

    def test_redacts_phone_in_sentence(self):
        assert redact("call 555-867-5309 now") == "call [REDACTED:PHONE] now"

    def test_does_not_redact_non_phone_numbers(self):
        assert redact("12345") == "12345"
        assert redact("the year 2024 was warm") == "the year 2024 was warm"


# --------------------------------------------------------------------------
# SSN
# --------------------------------------------------------------------------
class TestSsn:
    def test_redacts_ssn(self):
        assert redact("123-45-6789") == "[REDACTED:SSN]"

    def test_redacts_ssn_in_sentence(self):
        assert redact("ssn 123-45-6789 ok") == "ssn [REDACTED:SSN] ok"

    def test_does_not_redact_non_ssn(self):
        # No dashes -> not an SSN shape.
        assert redact("123456789") == "123456789"
        # Wrong grouping.
        assert redact("12-345-6789") == "12-345-6789"


# --------------------------------------------------------------------------
# Credit cards (Luhn-validated)
# --------------------------------------------------------------------------
class TestCreditCard:
    def test_redacts_valid_card(self):
        assert redact("4532015112830366") == "[REDACTED:CREDIT_CARD]"

    def test_redacts_card_in_sentence(self):
        out = redact("card 4532015112830366 charged")
        assert out == "card [REDACTED:CREDIT_CARD] charged"

    def test_does_not_redact_luhn_invalid_number(self):
        # Same digits, last one changed -> fails Luhn.
        assert redact("4532015112830367") == "4532015112830367"

    def test_does_not_redact_short_number(self):
        assert redact("1234") == "1234"


# --------------------------------------------------------------------------
# High-entropy secrets
# --------------------------------------------------------------------------
class TestHighEntropy:
    def test_redacts_high_entropy_secret(self):
        assert redact("xK9#mP2$vL8@nQ5!wR3") == "[REDACTED:SECRET]"

    def test_redacts_high_entropy_in_sentence(self):
        out = redact("token xK9#mP2$vL8@nQ5!wR3 set")
        assert out == "token [REDACTED:SECRET] set"

    def test_does_not_redact_short_random_string(self):
        assert redact("abc123") == "abc123"

    def test_does_not_redact_uuid(self):
        uid = "550e8400-e29b-41d4-a716-446655440000"
        assert redact(uid) == uid

    def test_does_not_redact_model_name(self):
        assert redact("claude-3-5-sonnet") == "claude-3-5-sonnet"
        assert redact("claude-3-5-sonnet-20241022") == "claude-3-5-sonnet-20241022"


# --------------------------------------------------------------------------
# General "should not redact" cases
# --------------------------------------------------------------------------
class TestShouldNotRedact:
    @pytest.mark.parametrize(
        "text",
        [
            "the weather is nice today",
            "https://api.example.com/v1/users",
            "/home/user/.dscan/traces/",
            "Search for recent news about AI security",
        ],
    )
    def test_leaves_benign_text_unchanged(self, text):
        assert redact(text) == text


# --------------------------------------------------------------------------
# Container handling: dicts (recursive, in-place) and lists
# --------------------------------------------------------------------------
class TestContainers:
    def test_redacts_dict_values_recursively(self):
        data = {
            "email": "user@example.com",
            "model": "claude-3-5-sonnet",
            "max_tokens": 1000,
            "nested": {"ssn": "123-45-6789", "note": "the weather is nice today"},
        }
        result = redact(data)
        assert result["email"] == "[REDACTED:EMAIL]"
        assert result["nested"]["ssn"] == "[REDACTED:SSN]"
        # Benign values untouched.
        assert result["model"] == "claude-3-5-sonnet"
        assert result["max_tokens"] == 1000
        assert result["nested"]["note"] == "the weather is nice today"

    def test_redacts_dict_in_place(self):
        data = {"email": "user@example.com"}
        result = redact(data)
        assert result is data  # same object, mutated in place
        assert data["email"] == "[REDACTED:EMAIL]"

    def test_does_not_redact_dict_keys(self):
        # An email-shaped *key* stays; only values are scrubbed.
        data = {"user@example.com": "ok"}
        result = redact(data)
        assert "user@example.com" in result
        assert result["user@example.com"] == "ok"

    def test_redacts_inside_lists(self):
        data = ["user@example.com", "harmless", "123-45-6789"]
        result = redact(data)
        assert result == ["[REDACTED:EMAIL]", "harmless", "[REDACTED:SSN]"]

    def test_redacts_lists_in_place(self):
        data = ["user@example.com"]
        result = redact(data)
        assert result is data
        assert data[0] == "[REDACTED:EMAIL]"

    def test_redacts_mixed_nested_structure(self):
        data = {
            "creds": ["AKIAIOSFODNN7EXAMPLE", {"token": "ghp_abc123xyz456"}],
            "count": 3,
            "active": True,
            "missing": None,
        }
        result = redact(data)
        assert result["creds"][0] == "[REDACTED:AWS_KEY]"
        assert result["creds"][1]["token"] == "[REDACTED:API_KEY]"
        # Non-string scalars pass through untouched.
        assert result["count"] == 3
        assert result["active"] is True
        assert result["missing"] is None

    def test_scalars_pass_through(self):
        assert redact(42) == 42
        assert redact(None) is None
        assert redact(True) is True
