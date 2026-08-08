"""Entropy pass: does it catch unknown-format keys without flagging prose?

The two failure modes that matter are on opposite ends: too strict and it
misses the custom tokens regex can't describe; too loose and every git SHA in
the repo becomes a finding. These tests pin both ends.
"""

import pytest

from entropy import (
    DEFAULT_CONFIG,
    EntropyConfig,
    find_high_entropy_strings,
    shannon_entropy,
)
from scanner_engine import find_secrets_in_text


# --- The math itself -----------------------------------------------------

def test_entropy_of_empty_and_uniform_strings():
    assert shannon_entropy("") == 0.0
    # One repeated character is perfectly predictable: zero bits.
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_entropy_matches_hand_calculation():
    # Four distinct characters, evenly distributed -> log2(4) = 2.0 bits.
    assert shannon_entropy("abcd") == pytest.approx(2.0)
    assert shannon_entropy("aabb") == pytest.approx(1.0)


def test_random_strings_score_higher_than_words():
    word = shannon_entropy("administratorpassword")
    random_key = shannon_entropy("kJ8xQm2vPzR7tYw3NcLb9FhD")
    assert random_key > word
    # The gap is the entire basis of the detector; make sure it's substantial.
    assert random_key - word > 0.5


# --- Catching what regex misses -----------------------------------------

# A plausible in-house credential: no vendor prefix, no recognizable shape, so
# no pattern in patterns.py can describe it.
CUSTOM_KEY = "kJ8xQm2vPzR7tYw3NcLb9FhD"

# Deliberately avoids the words key/token/secret/auth/password, so the generic
# keyword patterns can't fire either. Without this the test would pass for the
# wrong reason - a regex hit, not an entropy hit.
CUSTOM_LINE = f'INTERNAL_HANDSHAKE = "{CUSTOM_KEY}"'


def test_entropy_catches_random_key_that_regex_misses():
    line = CUSTOM_LINE

    # Confirm the premise: no regex pattern claims this string.
    regex_only = find_secrets_in_text(line, use_entropy=False)
    assert regex_only == [], f"expected no regex match, got {regex_only}"

    # The entropy pass finds it.
    tokens = [token for token, _span in find_high_entropy_strings(line)]
    assert CUSTOM_KEY in tokens


def test_entropy_finding_is_reported_as_low_confidence():
    hits = find_secrets_in_text(CUSTOM_LINE)

    assert len(hits) == 1
    assert hits[0]["type"] == "High-Entropy String"
    assert hits[0]["confidence"] == "low"
    # Masked like every other finding - never the raw value.
    assert CUSTOM_KEY not in hits[0]["match"]
    assert hits[0]["match"].endswith("*" * 8)


def test_entropy_catches_unquoted_assigned_value():
    line = f"INTERNAL_HANDSHAKE={CUSTOM_KEY}"
    tokens = [token for token, _span in find_high_entropy_strings(line)]
    assert CUSTOM_KEY in tokens


# --- Not flagging ordinary text -----------------------------------------

NORMAL_LINES = [
    'name = "administrator"',
    'password_field_label = "enteryourpasswordhere"',
    'description = "configuration"',
    'greeting = "HelloWorldThisIsALongString"',
    'path = "src/components/ResultsView.tsx"',
    'url = "https://example.com/documentation/getting-started"',
    'version = "1.24.3-beta.7"',
    'released = "2026-08-08T12:00:00Z"',
    'sentence = "the quick brown fox jumps over the lazy dog"',
    'klass = "flex items-center justify-between rounded-xl"',
]


@pytest.mark.parametrize("line", NORMAL_LINES)
def test_normal_words_are_not_flagged(line):
    assert find_high_entropy_strings(line) == [], f"false positive on: {line}"


NOISY_BUT_NOT_SECRET = [
    # git commit SHA-1
    'commit = "9c193cc7a4b1e0f8d2c3b5a6978e4f1d2c3b5a69"',
    # SHA-256 integrity hash
    'integrity = "a3f5b8c9d2e1f4a7b6c5d8e9f2a1b4c7d6e5f8a9b2c1d4e7f6a5b8c9d2e1f4a7"',
    # MD5
    'checksum = "d41d8cd98f00b204e9800998ecf8427e"',
    # UUID
    'request_id = "f47ac10b-58cc-4372-a567-0e02b2c3d479"',
    # Obvious placeholder
    'api_key = "your_api_key_here_xxxxxxxxxxxxxxxx"',
    # Repeated filler
    'token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa1"',
]


@pytest.mark.parametrize("line", NOISY_BUT_NOT_SECRET)
def test_random_looking_non_secrets_are_filtered(line):
    assert find_high_entropy_strings(line) == [], f"false positive on: {line}"


def test_short_strings_are_below_the_length_floor():
    # Random, but too short to be a credible key.
    assert find_high_entropy_strings('k = "aB3xQ9"') == []


# --- Second-pass behaviour ----------------------------------------------

def test_regex_matches_are_not_re_reported_by_entropy():
    """A known key must be reported once, by the rule that named it."""
    line = 'OPENAI_API_KEY = "sk-abc123XYZdef456UVWghi789RST"'
    hits = find_secrets_in_text(line)

    types = [h["type"] for h in hits]
    assert "OpenAI API Key" in types
    assert "High-Entropy String" not in types


def test_entropy_can_be_disabled():
    assert find_secrets_in_text(CUSTOM_LINE, use_entropy=False) == []

    disabled = EntropyConfig(enabled=False)
    assert find_high_entropy_strings(CUSTOM_LINE, config=disabled) == []


# --- Threshold is genuinely tunable -------------------------------------

def test_threshold_controls_sensitivity():
    # An impossibly high bar finds nothing...
    strict = EntropyConfig(base64_threshold=10.0)
    assert find_high_entropy_strings(CUSTOM_LINE, config=strict) == []

    # ...and a permissive one finds it.
    loose = EntropyConfig(base64_threshold=1.0)
    assert len(find_high_entropy_strings(CUSTOM_LINE, config=loose)) == 1


def test_default_threshold_separates_typical_words_from_keys():
    """Ordinary identifiers fall below the bar; random keys clear it."""
    words = [
        "administratorpassword",       # 3.33
        "configurationsettings",       # 3.43
        "enteryourpasswordhere",       # 3.44
        "documentationgettingstarted",  # 3.46
    ]
    keys = [CUSTOM_KEY, "Xq7Lm2Pv9Rt4Wz6Yb8Nc3Fd5", "a8Zk3Mq7Pw2Xv5Rt9Yb4Nc6L"]

    for word in words:
        assert shannon_entropy(word) < DEFAULT_CONFIG.base64_threshold
    for key in keys:
        assert shannon_entropy(key) >= DEFAULT_CONFIG.base64_threshold


def test_entropy_alone_is_insufficient_so_filters_carry_the_weight():
    """Entropy is a necessary signal, not a sufficient one.

    An unusually letter-diverse phrase can out-score the threshold - a pangram
    uses nearly the whole alphabet, which is exactly what entropy rewards. What
    actually rejects it is the mixed-charset filter: prose has no digits.
    Documented here because it's the detector's most load-bearing assumption.
    """
    phrase = "thequickbrownfoxjumped"

    # Entropy on its own is fooled...
    assert shannon_entropy(phrase) > DEFAULT_CONFIG.base64_threshold

    # ...but the full pass is not.
    assert find_high_entropy_strings(f'description = "{phrase}"') == []
