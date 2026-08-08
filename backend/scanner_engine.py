"""Secret-scanning engine.

Detection runs in two passes:

1. **Regex pass** - known credential formats from patterns.py. High confidence
   when the shape is provider-specific (`AKIA...`), medium for the generic
   keyword rules (`password = "..."`).
2. **Entropy pass** - entropy.py looks at whatever the regex pass did *not*
   claim and flags strings that are statistically random. Low confidence: it
   catches custom formats no pattern list covers, at the cost of needing
   review.

Every finding carries a `confidence` of "high", "medium", or "low" so callers
can rank or de-emphasize them.

No printing, no colors - the CLI (scan.py) and the FastAPI backend both import
from here.
"""

import os
import subprocess

import pathspec

from entropy import (
    DEFAULT_CONFIG as DEFAULT_ENTROPY_CONFIG,
    ENTROPY_FINDING_TYPE,
    EntropyConfig,
    find_high_entropy_strings,
    shannon_entropy,
)
from patterns import HIGH, LOW, MEDIUM, SECRET_PATTERNS

__all__ = [
    "scan_repo", "scan_file", "scan_directory", "scan_git_history",
    "find_secrets_in_text", "mask", "load_all_gitignores", "is_ignored",
    "shannon_entropy", "EntropyConfig", "DEFAULT_ENTROPY_CONFIG",
    "SECRET_PATTERNS", "SKIP_DIRS", "SKIP_EXTENSIONS",
    "HIGH", "MEDIUM", "LOW",
]

SKIP_DIRS = {".git", "venv", "node_modules", "__pycache__", ".venv", "dist", "build", ".idea", ".vscode"}
SKIP_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".exe", ".dll", ".pyc", ".ico", ".mp4", ".woff", ".woff2", ".ttf"}

# Files that are wall-to-wall content hashes and machine-generated ids. The
# regex pass still runs on them (a real key in a lockfile is worth knowing
# about); only the entropy pass is suppressed, because it would otherwise
# report every integrity digest in the file.
ENTROPY_SKIP_FILENAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock",
    "go.sum", "Gemfile.lock", "poetry.lock", "Cargo.lock", "flake.lock",
}
ENTROPY_SKIP_SUFFIXES = (".min.js", ".min.css", ".map", ".lock", ".snap")


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


def entropy_enabled_for(filename):
    """False for files that are legitimately full of random-looking strings."""
    name = os.path.basename(filename)
    if name in ENTROPY_SKIP_FILENAMES:
        return False
    return not name.endswith(ENTROPY_SKIP_SUFFIXES)


def find_secrets_in_text(text, entropy_config=None, use_entropy=True):
    """Return findings for one block of text.

    Each finding is {"type", "match", "confidence"}, with `match` already
    masked. The regex pass runs first and records the spans it matched; the
    entropy pass then examines only what is left over.
    """
    config = entropy_config or DEFAULT_ENTROPY_CONFIG
    hits = []
    matched_spans = []

    for pattern in SECRET_PATTERNS:
        for match in pattern.regex.finditer(text):
            value = match.group(0)
            if pattern.validator is not None and not pattern.validator(value):
                continue
            matched_spans.append(match.span())
            hits.append({
                "type": pattern.name,
                "match": mask(value),
                "confidence": pattern.confidence,
            })

    if use_entropy:
        for token, _span in find_high_entropy_strings(text, matched_spans, config):
            hits.append({
                "type": ENTROPY_FINDING_TYPE,
                "match": mask(token),
                "confidence": LOW,
                "entropy": round(shannon_entropy(token), 2),
            })

    return hits


def scan_file(filepath, entropy_config=None):
    findings = []
    use_entropy = entropy_enabled_for(filepath)
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, start=1):
                for hit in find_secrets_in_text(line, entropy_config, use_entropy):
                    findings.append({"file": filepath, "line": line_num, **hit})
    except Exception:
        pass
    return findings


def scan_directory(target, specs, entropy_config=None):
    findings = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext in SKIP_EXTENSIONS:
                continue
            path = os.path.join(root, filename)
            file_findings = scan_file(path, entropy_config)
            ignored = is_ignored(specs, path)
            for f in file_findings:
                f["ignored"] = ignored
            findings.extend(file_findings)
    return findings


def scan_git_history(target, on_warning=None, entropy_config=None):
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
                    for hit in find_secrets_in_text(line, entropy_config):
                        findings.append({"commit": commit[:8], **hit})
    except Exception as e:
        if on_warning is not None:
            on_warning(e)
        return []

    return findings


def scan_repo(target, on_warning=None, entropy_config=None):
    """Scan a folder (or single file) and return all findings grouped.

    Returns a dict:
      {
        "exposed":    [{"file", "line", "type", "match", "confidence"}, ...],
        "gitignored": [{"file", "line", "type", "match", "confidence"}, ...],
        "history":    [{"commit", "type", "match", "confidence"}, ...] or None,
      }
    Raises FileNotFoundError if target does not exist.
    """
    if not os.path.exists(target):
        raise FileNotFoundError(target)

    specs = load_all_gitignores(target)

    if os.path.isfile(target):
        all_findings = scan_file(target, entropy_config)
        for f in all_findings:
            f["ignored"] = False
    else:
        all_findings = scan_directory(target, specs, entropy_config)

    return {
        "exposed":    [f for f in all_findings if not f.get("ignored")],
        "gitignored": [f for f in all_findings if f.get("ignored")],
        "history":    scan_git_history(target, on_warning=on_warning,
                                       entropy_config=entropy_config),
    }
