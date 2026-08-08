"""Secret-scanning engine.

Detection logic extracted verbatim from the original scan.py CLI so it can be
imported by the FastAPI backend. No printing, no colors — every function
returns plain data. The CLI (scan.py at the repo root) and the web backend
both call into this module.
"""

import re
import os
import subprocess
import pathspec

SECRET_PATTERNS = [
    # --- Cloud providers ---
    ("AWS Access Key",          r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key",          r"(?i)aws_secret_access_key\s*[:=]\s*['\"][0-9a-zA-Z/+]{40}['\"]"),
    ("Google API Key",          r"AIza[0-9A-Za-z_-]{35}"),
    ("Google OAuth ID",         r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    ("Azure Storage Key",       r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+"),
    ("Heroku API Key",          r"(?i)heroku[a-z0-9_ .\-,]*[:=]\s*['\"][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['\"]"),

    # --- AI / LLM providers ---
    ("OpenAI API Key",          r"sk-[a-zA-Z0-9]{20,}"),
    ("OpenAI Project Key",      r"sk-proj-[a-zA-Z0-9_-]{20,}"),
    ("Anthropic API Key",       r"sk-ant-[a-zA-Z0-9_-]{20,}"),
    ("Hugging Face Token",      r"hf_[a-zA-Z0-9]{34}"),

    # --- Messaging / bots ---
    ("Telegram Bot Token",      r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}"),
    ("Slack Token",             r"xox[baprs]-[0-9a-zA-Z-]{10,}"),
    ("Slack Webhook",           r"https://hooks\.slack\.com/services/[A-Za-z0-9+/]{40,}"),
    ("Discord Bot Token",       r"[MNO][a-zA-Z0-9]{23}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}"),
    ("Discord Webhook",         r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+"),
    ("Twilio API Key",          r"SK[0-9a-fA-F]{32}"),
    ("SendGrid API Key",        r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"),
    ("Mailgun API Key",         r"key-[0-9a-zA-Z]{32}"),

    # --- Version control / CI ---
    ("GitHub Token",            r"gh[pousr]_[A-Za-z0-9]{36,}"),
    ("GitHub Fine-grained PAT", r"github_pat_[A-Za-z0-9_]{80,}"),
    ("GitLab Token",            r"glpat-[A-Za-z0-9_-]{20}"),
    ("NPM Token",               r"npm_[A-Za-z0-9]{36}"),

    # --- Payment ---
    ("Stripe Secret Key",       r"sk_live_[0-9a-zA-Z]{24,}"),
    ("Stripe Restricted Key",   r"rk_live_[0-9a-zA-Z]{24,}"),
    ("Stripe Publishable Key",  r"pk_live_[0-9a-zA-Z]{24,}"),
    ("Square Access Token",     r"sq0atp-[0-9A-Za-z_-]{22}"),
    ("PayPal Braintree Token",  r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),

    # --- Keys / certs ---
    ("Private Key",             r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ("SSH (ed25519) Private",   r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("PGP Private Key",         r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),

    # --- Databases / connection strings ---
    ("MongoDB URI",             r"mongodb(\+srv)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+"),
    ("PostgreSQL URI",          r"postgres(?:ql)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+"),
    ("MySQL URI",               r"mysql://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+"),
    ("Redis URI",               r"redis://[^\s'\"]*:[^\s'\"]+@[^\s'\"]+"),

    # --- Auth / tokens ---
    ("JWT",                     r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("Basic Auth in URL",       r"://[A-Za-z0-9._%-]+:[^\s'\"@/]+@"),

    # --- Generic fallbacks (broad - more false positives) ---
    ("Generic API Key",         r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][0-9a-zA-Z]{16,}['\"]"),
    ("Generic Password",        r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]"),
    ("Generic Secret/Token",    r"(?i)(secret|token|auth)\s*[:=]\s*['\"][0-9a-zA-Z_\-]{16,}['\"]"),
]

SKIP_DIRS = {".git", "venv", "node_modules", "__pycache__", ".venv", "dist", "build", ".idea", ".vscode"}
SKIP_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".exe", ".dll", ".pyc", ".ico", ".mp4", ".woff", ".woff2", ".ttf"}


def mask(secret):
    if len(secret) <= 8:
        return secret[:2] + "****"
    return secret[:6] + "*" * 8


def load_all_gitignores(target):
    specs = {}
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        if ".gitignore" in files:
            gitignore_path = os.path.join(root, ".gitignore")
            try:
                with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as f:
                    specs[root] = pathspec.PathSpec.from_lines("gitwildmatch", f)
            except Exception:
                pass
    return specs


def is_ignored(specs, filepath):
    for folder, spec in specs.items():
        try:
            rel = os.path.relpath(filepath, folder)
        except ValueError:
            continue
        if not rel.startswith(".."):
            rel_posix = rel.replace(os.sep, "/")
            if spec.match_file(rel_posix):
                return True
    return False


def find_secrets_in_text(text):
    """Return list of (type, masked) for all secrets in a block of text."""
    hits = []
    for name, pattern in SECRET_PATTERNS:
        for match in re.finditer(pattern, text):
            hits.append((name, mask(match.group(0))))
    return hits


def scan_file(filepath):
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, start=1):
                for name, masked in find_secrets_in_text(line):
                    findings.append({"file": filepath, "line": line_num,
                                     "type": name, "match": masked})
    except Exception:
        pass
    return findings


def scan_directory(target, specs):
    findings = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext in SKIP_EXTENSIONS:
                continue
            path = os.path.join(root, filename)
            file_findings = scan_file(path)
            ignored = is_ignored(specs, path)
            for f in file_findings:
                f["ignored"] = ignored
            findings.extend(file_findings)
    return findings


def scan_git_history(target, on_warning=None):
    """Scan the diffs of all past commits for secrets that may have been
    committed and later removed - they still live in git history.

    Returns None if target is not a git repo. On error, calls on_warning
    (if given) with the exception and returns []."""
    findings = []
    # Is this a git repo?
    if not os.path.isdir(os.path.join(target, ".git")):
        return None  # signal: not a git repo

    try:
        # Get all commit hashes
        commits = subprocess.run(
            ["git", "-C", target, "log", "--pretty=format:%H"],
            capture_output=True, text=True, timeout=60
        ).stdout.split()

        for commit in commits:
            # Get what this commit ADDED (the diff), scan added lines
            diff = subprocess.run(
                ["git", "-C", target, "show", commit, "--no-color", "--unified=0"],
                capture_output=True, text=True, timeout=30, errors="ignore"
            ).stdout

            for line in diff.splitlines():
                # Only look at ADDED lines (start with + but not +++ header)
                if line.startswith("+") and not line.startswith("+++"):
                    for name, masked in find_secrets_in_text(line):
                        findings.append({"commit": commit[:8], "type": name, "match": masked})
    except Exception as e:
        if on_warning is not None:
            on_warning(e)
        return []

    return findings


def scan_repo(target, on_warning=None):
    """Scan a folder (or single file) and return all findings grouped.

    Returns a dict:
      {
        "exposed":    [{"file", "line", "type", "match"}, ...],
        "gitignored": [{"file", "line", "type", "match"}, ...],
        "history":    [{"commit", "type", "match"}, ...] or None if not a git repo,
      }
    Raises FileNotFoundError if target does not exist.
    """
    if not os.path.exists(target):
        raise FileNotFoundError(target)

    specs = load_all_gitignores(target)

    if os.path.isfile(target):
        all_findings = scan_file(target)
        for f in all_findings:
            f["ignored"] = False
    else:
        all_findings = scan_directory(target, specs)

    return {
        "exposed":    [f for f in all_findings if not f.get("ignored")],
        "gitignored": [f for f in all_findings if f.get("ignored")],
        "history":    scan_git_history(target, on_warning=on_warning),
    }
