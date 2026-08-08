"""Known-format secret patterns, with confidence ratings and validators.

Every pattern from the original scan.py is preserved here verbatim - only
metadata (a confidence rating, an optional validator) has been wrapped around
it. New provider patterns are appended in their own sections.

Confidence ratings
------------------
HIGH    A provider-specific key shape. `AKIA...` is an AWS access key and
        essentially nothing else, so a match is near-certain to be a real
        credential.
MEDIUM  Evidence of a credential without a distinctive shape: the generic
        keyword patterns (`password = "..."`), JWTs, and Luhn-valid card
        numbers. Real hits, but this is where the false positives live.
LOW     Reserved for entropy-only findings (see entropy.py) - no known format
        matched, the string just looks random.
"""

import re
from dataclasses import dataclass
from typing import Callable, Optional

HIGH = "high"
MEDIUM = "medium"
LOW = "low"


@dataclass(frozen=True)
class Pattern:
    name: str
    regex: "re.Pattern[str]"
    confidence: str
    # Optional second check on the matched text. Returning False discards the
    # match, which is how card numbers are Luhn-filtered.
    validator: Optional[Callable[[str], bool]] = None


# --- Credit card validation ---------------------------------------------

# Card numbers published in payment-provider docs. They are Luhn-valid by
# design and appear in almost every integration example, so they are noise.
TEST_CARD_NUMBERS = {
    "4111111111111111", "4012888888881881", "4222222222222",
    "4242424242424242", "4000056655665556", "5555555555554444",
    "5105105105105100", "5200828282828210", "378282246310005",
    "371449635398431", "378734493671000", "6011111111111117",
    "6011000990139424", "3530111333300000", "3566002020360505",
    "6200000000000005", "4761739001010119",
}


def luhn_valid(number: str) -> bool:
    """The Luhn checksum used by every major card network.

    Double every second digit counting from the right; if doubling pushes a
    digit past 9, subtract 9. A valid number's digits sum to a multiple of 10.
    This rejects roughly 90% of random digit runs, which is what makes a card
    regex usable at all - without it, any 16-digit order ID would match.
    """
    digits = [int(d) for d in re.sub(r"[^0-9]", "", number)]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _valid_card(matched: str) -> bool:
    normalized = re.sub(r"[^0-9]", "", matched)
    if normalized in TEST_CARD_NUMBERS:
        return False
    return luhn_valid(normalized)


# --- Pattern definitions -------------------------------------------------

# (name, regex, confidence, validator)
_DEFINITIONS = [
    # === Original scan.py patterns (unchanged) ===========================

    # --- Cloud providers ---
    ("AWS Access Key",          r"AKIA[0-9A-Z]{16}", HIGH),
    ("AWS Secret Key",          r"(?i)aws_secret_access_key\s*[:=]\s*['\"][0-9a-zA-Z/+]{40}['\"]", HIGH),
    ("Google API Key",          r"AIza[0-9A-Za-z_-]{35}", HIGH),
    ("Google OAuth ID",         r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", HIGH),
    ("Azure Storage Key",       r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+", HIGH),
    ("Heroku API Key",          r"(?i)heroku[a-z0-9_ .\-,]*[:=]\s*['\"][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['\"]", HIGH),

    # --- AI / LLM providers ---
    ("OpenAI API Key",          r"sk-[a-zA-Z0-9]{20,}", HIGH),
    ("OpenAI Project Key",      r"sk-proj-[a-zA-Z0-9_-]{20,}", HIGH),
    ("Anthropic API Key",       r"sk-ant-[a-zA-Z0-9_-]{20,}", HIGH),
    ("Hugging Face Token",      r"hf_[a-zA-Z0-9]{34}", HIGH),

    # --- Messaging / bots ---
    ("Telegram Bot Token",      r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}", HIGH),
    ("Slack Token",             r"xox[baprs]-[0-9a-zA-Z-]{10,}", HIGH),
    ("Slack Webhook",           r"https://hooks\.slack\.com/services/[A-Za-z0-9+/]{40,}", HIGH),
    ("Discord Bot Token",       r"[MNO][a-zA-Z0-9]{23}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}", HIGH),
    ("Discord Webhook",         r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+", HIGH),
    ("Twilio API Key",          r"SK[0-9a-fA-F]{32}", HIGH),
    ("SendGrid API Key",        r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", HIGH),
    ("Mailgun API Key",         r"key-[0-9a-zA-Z]{32}", HIGH),

    # --- Version control / CI ---
    ("GitHub Token",            r"gh[pousr]_[A-Za-z0-9]{36,}", HIGH),
    ("GitHub Fine-grained PAT", r"github_pat_[A-Za-z0-9_]{80,}", HIGH),
    ("GitLab Token",            r"glpat-[A-Za-z0-9_-]{20}", HIGH),
    ("NPM Token",               r"npm_[A-Za-z0-9]{36}", HIGH),

    # --- Payment ---
    ("Stripe Secret Key",       r"sk_live_[0-9a-zA-Z]{24,}", HIGH),
    ("Stripe Restricted Key",   r"rk_live_[0-9a-zA-Z]{24,}", HIGH),
    ("Stripe Publishable Key",  r"pk_live_[0-9a-zA-Z]{24,}", HIGH),
    ("Square Access Token",     r"sq0atp-[0-9A-Za-z_-]{22}", HIGH),
    ("PayPal Braintree Token",  r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", HIGH),

    # --- Keys / certs ---
    ("Private Key",             r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", HIGH),
    ("SSH (ed25519) Private",   r"-----BEGIN OPENSSH PRIVATE KEY-----", HIGH),
    ("PGP Private Key",         r"-----BEGIN PGP PRIVATE KEY BLOCK-----", HIGH),

    # --- Databases / connection strings ---
    ("MongoDB URI",             r"mongodb(\+srv)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", HIGH),
    ("PostgreSQL URI",          r"postgres(?:ql)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", HIGH),
    ("MySQL URI",               r"mysql://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", HIGH),
    ("Redis URI",               r"redis://[^\s'\"]*:[^\s'\"]+@[^\s'\"]+", HIGH),

    # --- Auth / tokens ---
    # JWTs are frequently sample/expired tokens pasted into docs and tests,
    # so they rate below provider-specific keys.
    ("JWT",                     r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", MEDIUM),
    ("Basic Auth in URL",       r"://[A-Za-z0-9._%-]+:[^\s'\"@/]+@", MEDIUM),

    # --- Generic fallbacks (broad - more false positives) ---
    ("Generic API Key",         r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][0-9a-zA-Z]{16,}['\"]", MEDIUM),
    ("Generic Password",        r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]", MEDIUM),
    ("Generic Secret/Token",    r"(?i)(secret|token|auth)\s*[:=]\s*['\"][0-9a-zA-Z_\-]{16,}['\"]", MEDIUM),

    # === v2 additions ====================================================

    # --- More cloud providers ---
    ("DigitalOcean PAT",        r"dop_v1_[a-f0-9]{64}", HIGH),
    ("DigitalOcean OAuth Token", r"do[or]_v1_[a-f0-9]{64}", HIGH),
    ("Cloudflare API Token",    r"(?i)cloudflare[a-z0-9_ .\-,]*[:=]\s*['\"][A-Za-z0-9_-]{40}['\"]", HIGH),
    ("Cloudflare Global Key",   r"(?i)cf[_-]?(?:global[_-]?)?api[_-]?key\s*[:=]\s*['\"][0-9a-f]{37}['\"]", HIGH),
    ("Oracle Cloud OCID",       r"ocid1\.(?:user|tenancy|fingerprint)\.oc[0-9]+\.\.[a-z0-9]{20,}", HIGH),
    ("Alibaba Access Key ID",   r"LTAI[A-Za-z0-9]{12,20}", HIGH),
    ("Alibaba Secret Key",      r"(?i)alibaba|aliyun[a-z0-9_ .\-,]*secret[a-z0-9_ .\-,]*[:=]\s*['\"][A-Za-z0-9]{30}['\"]", HIGH),

    # --- More AI providers ---
    ("Groq API Key",            r"gsk_[A-Za-z0-9]{52}", HIGH),
    ("Replicate API Token",     r"r8_[A-Za-z0-9]{37,}", HIGH),
    ("Perplexity API Key",      r"pplx-[A-Za-z0-9]{32,}", HIGH),
    ("Cohere API Key",          r"(?i)cohere[a-z0-9_ .\-,]*[:=]\s*['\"][A-Za-z0-9]{40}['\"]", HIGH),
    ("Mistral API Key",         r"(?i)mistral[a-z0-9_ .\-,]*[:=]\s*['\"][A-Za-z0-9]{32}['\"]", HIGH),

    # --- Indonesian payment providers ---
    # Midtrans ships sandbox (SB-) and production variants of both keys.
    ("Midtrans Server Key",     r"(?:SB-)?Mid-server-[A-Za-z0-9_-]{20,}", HIGH),
    ("Midtrans Client Key",     r"(?:SB-)?Mid-client-[A-Za-z0-9_-]{20,}", HIGH),
    ("Xendit Secret Key",       r"xnd_(?:development|production)_[A-Za-z0-9_=+/-]{20,}", HIGH),
    ("Xendit Public Key",       r"xnd_public_(?:development|production)_[A-Za-z0-9_=+/-]{20,}", HIGH),
    ("DANA Client Secret",      r"(?i)dana[a-z0-9_ .\-,]*(?:client[_-]?secret|private[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{20,}['\"]", HIGH),
    ("GoPay Credential",        r"(?i)gopay[a-z0-9_ .\-,]*(?:secret|key|token)\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{20,}['\"]", HIGH),
    ("Doku Secret Key",         r"(?i)doku[a-z0-9_ .\-,]*(?:secret|shared)[a-z0-9_ .\-,]*key\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{16,}['\"]", HIGH),

    # --- Payment card numbers (Luhn-validated below) ---
    ("Credit Card Number",
     r"\b(?:3[47]\d{2}|4\d{3}|5[1-5]\d{2}|6(?:011|5\d{2})|35\d{2})(?:[ -]?\d{4}){2}[ -]?\d{1,7}\b",
     MEDIUM, _valid_card),

    # --- More database connection strings ---
    ("MSSQL Connection String", r"(?i)(?:Server|Data Source)=[^;]+;(?:[^;]*;)*\s*(?:Password|Pwd)=[^;\s'\"]+", HIGH),
    ("JDBC Connection String",  r"(?i)jdbc:[a-z0-9]+://[^\s'\"]*[?&;](?:password|pwd)=[^\s'\"&;]+", HIGH),
    ("Oracle Connection",       r"(?i)jdbc:oracle:thin:[^\s'\"/@]+/[^\s'\"@]+@[^\s'\"]+", HIGH),
    ("AMQP/RabbitMQ URI",       r"amqps?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", HIGH),
    ("Neo4j Bolt URI",          r"bolt(?:\+s(?:sc)?)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", HIGH),
    ("Cassandra/Scylla URI",    r"cassandra://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", HIGH),
    ("ClickHouse URI",          r"clickhouse://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", HIGH),
    ("Elasticsearch URI",       r"https?://[A-Za-z0-9._%-]+:[^\s'\"@/]+@[^\s'\"]*(?:elastic|es)[^\s'\"]*", HIGH),

    # --- OAuth client secrets ---
    ("Google OAuth Secret",     r"GOCSPX-[A-Za-z0-9_-]{28}", HIGH),
    ("Facebook App Secret",     r"(?i)(?:facebook|fb)[a-z0-9_ .\-,]*(?:app[_-]?secret|client[_-]?secret)\s*[:=]\s*['\"][0-9a-f]{32}['\"]", HIGH),
    ("GitHub OAuth Secret",     r"(?i)github[a-z0-9_ .\-,]*client[_-]?secret\s*[:=]\s*['\"][0-9a-f]{40}['\"]", HIGH),
    ("Generic OAuth Secret",    r"(?i)client[_-]?secret\s*[:=]\s*['\"][A-Za-z0-9_\-./+=]{16,}['\"]", MEDIUM),

    # --- Webhook URLs carrying a token ---
    ("Microsoft Teams Webhook", r"https://[a-z0-9-]+\.webhook\.office\.com/webhookb2/[A-Za-z0-9@/-]{20,}", HIGH),
    ("Zapier Webhook",          r"https://hooks\.zapier\.com/hooks/catch/[0-9]+/[A-Za-z0-9]+", HIGH),
    ("Telegram Webhook",        r"https://api\.telegram\.org/bot[0-9]{8,10}:[A-Za-z0-9_-]{35}/", HIGH),
    ("Twilio Webhook Auth",     r"https://[A-Z0-9]{34}:[0-9a-f]{32}@api\.twilio\.com", HIGH),
]


def _build():
    built = []
    for definition in _DEFINITIONS:
        name, regex, confidence = definition[0], definition[1], definition[2]
        validator = definition[3] if len(definition) > 3 else None
        built.append(Pattern(name, re.compile(regex), confidence, validator))
    return built


SECRET_PATTERNS = _build()
