"""Second-pass detection: flag high-entropy strings no known pattern matched.

Why entropy works
-----------------
Shannon entropy measures how unpredictable a string is, in bits per character:

    H = -sum over distinct characters c of  p(c) * log2 p(c)

where p(c) is how often c appears. Text that reuses a few characters scores
low; text that spreads evenly across a large alphabet scores high. English
words land around 3.0 and below because letters repeat heavily. A randomly
generated key uses its whole alphabet about evenly, so it approaches the
theoretical ceiling: log2(16) = 4.0 for hex, log2(64) = 6.0 for base64.

That gap is the whole signal. Regex catches formats we can name; entropy
catches the rest - a custom or in-house token no pattern list will ever cover.

The catch: entropy alone is noisy
---------------------------------
Plenty of non-secrets are also random-looking - git SHAs, UUIDs, content
hashes, minified identifiers. Raw entropy would flag all of them. So a
candidate must clear several filters (see `_is_plausible_secret`) before its
entropy is even considered. Entropy findings are therefore rated LOW
confidence: a broad net that still needs human eyes.

One subtlety worth knowing when tuning: a string of length n cannot score
above log2(n), because it has at most n distinct characters. A 20-character
string caps at 4.32 bits regardless of how random it is. That is why the
base64 threshold sits at 4.0 rather than the 4.5 you may have seen elsewhere -
with a 20-character minimum, 4.5 would be nearly unreachable.

Tuning
------
Adjust DEFAULT_CONFIG below, pass your own EntropyConfig to the scan
functions, or set the LEAKSCAN_ENTROPY_* environment variables.
"""

import base64
import binascii
import math
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Sequence, Tuple


@dataclass(frozen=True)
class EntropyConfig:
    """Everything tunable about the entropy pass, in one place."""

    enabled: bool = True

    # Shorter strings are too weak a signal (and cap out below the threshold
    # anyway); much longer ones are usually embedded data, not credentials.
    min_length: int = 20
    max_length: int = 200

    # Bits per character, by alphabet. Hex has a 4.0 ceiling so its bar sits
    # lower than base64's.
    base64_threshold: float = 4.0
    hex_threshold: float = 3.0

    # Require at least one letter AND one digit. Prose, identifiers, and
    # dictionary words fail this outright, which removes most false positives
    # before entropy is even computed.
    require_mixed_charset: bool = True

    # A randomly generated 20+ character key drawn from base62 contains about
    # three digits on average; having fewer than two is rare enough (~2%) that
    # requiring two is nearly free. Camel-case identifiers like
    # `sourceMappingURL2`, which otherwise sail through, do not survive it.
    min_digits: int = 2

    # Pure-hex strings of exactly these lengths are almost always MD5 / SHA-1 /
    # SHA-256 digests - git object ids, lockfile integrity hashes, ETags.
    skip_hex_digest_lengths: frozenset = field(
        default_factory=lambda: frozenset({32, 40, 64})
    )


def _config_from_env() -> EntropyConfig:
    """Allow tuning without editing code (handy when triaging a noisy repo)."""

    def number(name, fallback, cast):
        raw = os.environ.get(name)
        if raw is None:
            return fallback
        try:
            return cast(raw)
        except ValueError:
            return fallback

    return EntropyConfig(
        enabled=os.environ.get("LEAKSCAN_ENTROPY_ENABLED", "1") != "0",
        min_length=number("LEAKSCAN_ENTROPY_MIN_LENGTH", 20, int),
        base64_threshold=number("LEAKSCAN_ENTROPY_BASE64_THRESHOLD", 4.0, float),
        hex_threshold=number("LEAKSCAN_ENTROPY_HEX_THRESHOLD", 3.0, float),
    )


DEFAULT_CONFIG = _config_from_env()

# The label attached to entropy findings.
ENTROPY_FINDING_TYPE = "High-Entropy String"


def shannon_entropy(data: str) -> float:
    """Bits of entropy per character. See the module docstring for the math."""
    if not data:
        return 0.0
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in Counter(data).values()
    )


# --- Candidate extraction ------------------------------------------------

# Secrets live in value positions, not scattered through prose. Restricting
# candidates to quoted literals and assigned values is the single biggest
# noise reduction available, so it happens before any entropy math.
#
# Both use the same restricted alphabet. Credentials are drawn from base64,
# base62, or hex plus a few separators - they never contain `(){};,`. Allowing
# arbitrary punctuation here means capturing minified JavaScript and inline SQL,
# which are dense, random-looking, and entirely not secrets.
_TOKEN_CHARS = r"[A-Za-z0-9+/=_.~-]"
_QUOTED = re.compile(rf"['\"]({_TOKEN_CHARS}{{8,400}})['\"]")
_ASSIGNED = re.compile(rf"[:=]\s*({_TOKEN_CHARS}{{8,400}})")

_HEX_ONLY = re.compile(r"^[0-9a-fA-F]+$")
_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HAS_LETTER = re.compile(r"[A-Za-z]")
_HAS_DIGIT = re.compile(r"[0-9]")
_REPEATED_RUN = re.compile(r"(.)\1{5,}")

# Obvious stand-ins. These are frequently high-entropy by accident and never
# real credentials.
_PLACEHOLDER_WORDS = re.compile(
    r"(?i)(example|placeholder|redacted|dummy|sample|changeme|your[_-]?(api|key|token|secret)|"
    r"xxxxx|insert[_-]?here|not[_-]?a[_-]?real)"
)

# Things that are structurally random but semantically public.
_LOOKS_LIKE_URL = re.compile(r"(?i)^[a-z][a-z0-9+.-]*://")
_LOOKS_LIKE_PATH = re.compile(r"^[./~]|/[a-z]+\.[a-z]{2,4}$")
_LOOKS_LIKE_VERSION = re.compile(r"^[0-9]+\.[0-9.]+(?:[-+][A-Za-z0-9.]+)?$")
_LOOKS_LIKE_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}")


_BASE64_ONLY = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def _is_encoded_text(token: str) -> bool:
    """True when the token is base64 that decodes to readable text.

    Encoded copy, config blobs, and data payloads are legitimately high-entropy
    but are not credentials. Random key material decoding to clean ASCII is
    effectively impossible, so this is a safe discriminator.
    """
    if len(token) % 4 or not _BASE64_ONLY.match(token):
        return False
    try:
        decoded = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return False
    if not decoded:
        return False
    printable = sum(1 for b in decoded if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(decoded) > 0.9


def _charset_threshold(token: str, config: EntropyConfig) -> float:
    if _HEX_ONLY.match(token):
        return config.hex_threshold
    return config.base64_threshold


def _is_plausible_secret(token: str, config: EntropyConfig) -> bool:
    """Cheap structural filters, applied before the entropy check."""
    if not config.min_length <= len(token) <= config.max_length:
        return False

    if config.require_mixed_charset:
        if not (_HAS_LETTER.search(token) and _HAS_DIGIT.search(token)):
            return False
        if len(_HAS_DIGIT.findall(token)) < config.min_digits:
            return False

    if _is_encoded_text(token):
        return False

    if _UUID.match(token):
        return False

    if _HEX_ONLY.match(token) and len(token) in config.skip_hex_digest_lengths:
        return False

    if _REPEATED_RUN.search(token):
        return False

    if _PLACEHOLDER_WORDS.search(token):
        return False

    if (
        _LOOKS_LIKE_URL.match(token)
        or _LOOKS_LIKE_PATH.search(token)
        or _LOOKS_LIKE_VERSION.match(token)
        or _LOOKS_LIKE_DATE.match(token)
    ):
        return False

    return True


def _overlaps(span: Tuple[int, int], occupied: Sequence[Tuple[int, int]]) -> bool:
    start, end = span
    return any(start < taken_end and taken_start < end for taken_start, taken_end in occupied)


def find_high_entropy_strings(
    text: str,
    occupied_spans: Sequence[Tuple[int, int]] = (),
    config: EntropyConfig = DEFAULT_CONFIG,
) -> List[Tuple[str, Tuple[int, int]]]:
    """Return [(token, span)] for high-entropy strings in `text`.

    `occupied_spans` are regions already claimed by a regex pattern. Skipping
    them is what makes this a genuine *second* pass: known formats are reported
    once, by the rule that named them, and never re-reported as anonymous
    high-entropy blobs.
    """
    if not config.enabled:
        return []

    findings = []
    seen = set()

    for matcher in (_QUOTED, _ASSIGNED):
        for match in matcher.finditer(text):
            token = match.group(1)
            span = match.span(1)

            if span in seen or _overlaps(span, occupied_spans):
                continue
            if not _is_plausible_secret(token, config):
                continue
            if shannon_entropy(token) < _charset_threshold(token, config):
                continue

            seen.add(span)
            findings.append((token, span))

    return findings
