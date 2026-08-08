"""Regex pass: new provider patterns, Luhn validation, confidence ratings."""

import pytest

from patterns import luhn_valid
from scanner_engine import find_secrets_in_text


def types_in(line):
    return {hit["type"] for hit in find_secrets_in_text(line, use_entropy=False)}


def confidence_of(line, type_name):
    for hit in find_secrets_in_text(line, use_entropy=False):
        if hit["type"] == type_name:
            return hit["confidence"]
    raise AssertionError(f"{type_name} not found in: {line}")


# --- Original patterns still fire ---------------------------------------

ORIGINAL_CASES = [
    ("AKIAIOSFODNN7EXAMPLE", "AWS Access Key"),
    ("AIzaSyA1234567890abcdefghijklmnopqrstuv", "Google API Key"),
    ("sk-abcdefghijklmnopqrstuvwx", "OpenAI API Key"),
    ("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "GitHub Token"),
    ("xoxb-123456789012-abcdefGHIJKL", "Slack Token"),
    ("-----BEGIN RSA PRIVATE KEY-----", "Private Key"),
]


@pytest.mark.parametrize("value,expected", ORIGINAL_CASES)
def test_original_patterns_unchanged(value, expected):
    assert expected in types_in(value)


# --- New provider patterns ----------------------------------------------

NEW_CASES = [
    # Cloud
    ("dop_v1_" + "a" * 64, "DigitalOcean PAT"),
    ('cloudflare_api_token = "' + "A" * 40 + '"', "Cloudflare API Token"),
    ("ocid1.tenancy.oc1..aaaaaaaabcdefghijklmnopqrstuvwxyz123456", "Oracle Cloud OCID"),
    ("LTAI5tR8xQm2vPzR7tYw", "Alibaba Access Key ID"),
    # AI
    ("gsk_" + "b" * 52, "Groq API Key"),
    ("r8_" + "c" * 37, "Replicate API Token"),
    ("pplx-" + "d" * 32, "Perplexity API Key"),
    ('cohere_api_key = "' + "e" * 40 + '"', "Cohere API Key"),
    ('mistral_api_key = "' + "f" * 32 + '"', "Mistral API Key"),
    # Indonesian payment providers
    ("SB-Mid-server-Kx8vQm2vPzR7tYw3NcLb9FhD", "Midtrans Server Key"),
    ("Mid-client-Kx8vQm2vPzR7tYw3NcLb9FhD", "Midtrans Client Key"),
    ("xnd_development_Kx8vQm2vPzR7tYw3NcLb9FhD", "Xendit Secret Key"),
    ('dana_client_secret = "Kx8vQm2vPzR7tYw3NcLb9FhD"', "DANA Client Secret"),
    ('gopay_secret = "Kx8vQm2vPzR7tYw3NcLb9FhD"', "GoPay Credential"),
    # OAuth
    ("GOCSPX-abcdefghijklmnopqrstuvwxyz12", "Google OAuth Secret"),
    ('client_secret = "Kx8vQm2vPzR7tYw3NcLb9FhD"', "Generic OAuth Secret"),
    # Databases
    ("amqp://user:hunter2@rabbit.internal:5672", "AMQP/RabbitMQ URI"),
    ("bolt://neo4j:hunter2@graph.internal:7687", "Neo4j Bolt URI"),
    ("jdbc:oracle:thin:scott/tiger@//db.internal:1521/ORCL", "Oracle Connection"),
    # Webhooks
    ("https://hooks.zapier.com/hooks/catch/123456/abcdef", "Zapier Webhook"),
]


@pytest.mark.parametrize("value,expected", NEW_CASES)
def test_new_patterns_match(value, expected):
    assert expected in types_in(value)


# --- Luhn validation ----------------------------------------------------

def test_luhn_accepts_valid_numbers():
    assert luhn_valid("4539578763621486")
    assert luhn_valid("6011000990139424")


def test_luhn_rejects_invalid_numbers():
    # Same digits, one transposed - the checksum catches it.
    assert not luhn_valid("4539578763621487")
    assert not luhn_valid("1234567812345678")


def test_card_number_requires_luhn_validity():
    # Luhn-valid, not a published test card -> reported.
    assert "Credit Card Number" in types_in("card = 4539578763621486")

    # Right shape, fails the checksum -> discarded. This is what stops random
    # 16-digit ids (order numbers, timestamps) from becoming findings.
    assert "Credit Card Number" not in types_in("order_id = 4539578763621487")


def test_published_test_cards_are_ignored():
    """Every payment integration doc contains these; they are not leaks."""
    for test_card in ("4111111111111111", "4242424242424242", "378282246310005"):
        assert "Credit Card Number" not in types_in(f"card = {test_card}")


def test_card_with_separators_is_detected():
    assert "Credit Card Number" in types_in("card = 4539-5787-6362-1486")


# --- Confidence scoring -------------------------------------------------

def test_specific_patterns_are_high_confidence():
    assert confidence_of("AKIAIOSFODNN7EXAMPLE", "AWS Access Key") == "high"
    assert confidence_of("sk-abcdefghijklmnopqrstuvwx", "OpenAI API Key") == "high"


def test_generic_patterns_are_medium_confidence():
    assert confidence_of('password = "hunter2pass"', "Generic Password") == "medium"
    assert confidence_of('api_key = "abcdefghijklmnop"', "Generic API Key") == "medium"


def test_confidence_ranks_generic_below_specific():
    """The noise problem in one assertion: a real key outranks a keyword hit."""
    order = {"high": 3, "medium": 2, "low": 1}
    specific = confidence_of("AKIAIOSFODNN7EXAMPLE", "AWS Access Key")
    generic = confidence_of('password = "hunter2pass"', "Generic Password")
    assert order[specific] > order[generic]


def test_every_finding_carries_a_confidence():
    line = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # password = "hunter2pass"'
    hits = find_secrets_in_text(line)
    assert hits
    assert all(h["confidence"] in {"high", "medium", "low"} for h in hits)
