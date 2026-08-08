"""FastAPI backend for the repo secret scanner.

One endpoint: POST /scan. Takes a public github.com repo URL, shallow-clones
it to a temp dir, runs the scanning engine, returns grouped masked findings,
and always deletes the clone.
"""

import json
import logging
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from scanner_engine import scan_repo

# --- Limits (security constraints from CLAUDE.md) ---
MAX_REPO_SIZE_KB = 100 * 1024   # 100 MB reported by GitHub API
CLONE_DEPTH = 50                # shallow clone; caps git-history scan depth
CLONE_TIMEOUT_S = 90
GITHUB_API_TIMEOUT_S = 10

GITHUB_URL_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/"
    r"(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/"
    r"(?P<repo>[A-Za-z0-9._-]{1,100}?)(?:\.git)?/?$"
)

log = logging.getLogger("leakscan")

# Any localhost port, so `next dev` works whichever port it lands on.
LOCAL_DEV_ORIGIN_RE = r"https?://(localhost|127\.0\.0\.1)(:\d+)?"


def cors_options():
    """Explicit origins in production, any localhost port in development.

    ALLOWED_ORIGINS is a comma-separated list (set it to the Vercel domain).
    Leaving it unset does NOT fall back to a wildcard - an unconfigured
    deployment fails closed with a CORS error rather than silently serving
    every origin on the internet.
    """
    configured = os.environ.get("ALLOWED_ORIGINS", "").strip()
    if configured:
        origins = [origin.strip() for origin in configured.split(",") if origin.strip()]
        return {"allow_origins": origins}

    return {"allow_origin_regex": LOCAL_DEV_ORIGIN_RE}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Logged here rather than at import time: uvicorn installs its handlers
    # during startup, so anything emitted earlier is discarded - and this line
    # exists precisely to make the deployed CORS config visible in the logs.
    allowed = os.environ.get("ALLOWED_ORIGINS", "").strip()
    if allowed:
        log.info("CORS restricted to: %s", allowed)
    else:
        log.warning(
            "ALLOWED_ORIGINS unset - allowing localhost only. A deployed "
            "frontend will be blocked until this is set."
        )

    sweep_stale_clones()
    yield


app = FastAPI(title="Repo Secret Scanner", version="0.2.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
    **cors_options(),
)


class ScanRequest(BaseModel):
    repo_url: str


def parse_github_url(url: str):
    """Return (owner, repo) or raise 400 for anything that isn't a github.com repo URL."""
    m = GITHUB_URL_RE.match(url.strip())
    if not m:
        raise HTTPException(
            status_code=400,
            detail="Not a valid GitHub repository URL. Expected https://github.com/<owner>/<repo>",
        )
    return m.group("owner"), m.group("repo")


def check_repo_public_and_size(owner: str, repo: str):
    """Ask the GitHub API whether the repo exists publicly and is under the size cap."""
    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    req = urllib.request.Request(api_url, headers={"User-Agent": "repo-secret-scanner"})
    try:
        with urllib.request.urlopen(req, timeout=GITHUB_API_TIMEOUT_S) as resp:
            info = json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise HTTPException(
                status_code=404,
                detail="Repository not found on GitHub - it may be private or the URL is wrong.",
            )
        if e.code == 403:
            # GitHub API rate limit - don't block the scan, the clone itself will
            # still fail for private/nonexistent repos.
            return
        raise HTTPException(status_code=502, detail=f"GitHub API error ({e.code}).")
    except urllib.error.URLError:
        raise HTTPException(status_code=502, detail="Could not reach GitHub to verify the repository.")

    if info.get("private"):
        raise HTTPException(status_code=404, detail="Repository is private - only public repos can be scanned.")
    size_kb = info.get("size", 0)
    if size_kb > MAX_REPO_SIZE_KB:
        raise HTTPException(
            status_code=413,
            detail=f"Repository is too large to scan ({size_kb // 1024} MB, limit {MAX_REPO_SIZE_KB // 1024} MB).",
        )


def clone_repo(owner: str, repo: str, dest: str):
    clone_url = f"https://github.com/{owner}/{repo}.git"
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}  # never prompt for credentials
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", str(CLONE_DEPTH), "--no-tags", "--single-branch",
             clone_url, dest],
            capture_output=True, text=True, timeout=CLONE_TIMEOUT_S, env=env,
        )
    except subprocess.TimeoutExpired:
        log.warning("git clone timed out after %ss: %s/%s", CLONE_TIMEOUT_S, owner, repo)
        raise HTTPException(status_code=504, detail="Cloning the repository timed out.")

    if result.returncode != 0:
        # Log git's own explanation server-side. The client still gets a generic
        # message - stderr can echo back a URL, and a credential-bearing URL must
        # never reach an HTTP response - but without this, a failed scan is
        # undiagnosable once the request is over.
        log.warning(
            "git clone failed for %s/%s (exit %s): %s",
            owner, repo, result.returncode, result.stderr.strip()[:500],
        )

        # Map git's stderr onto a useful status. This matters when the GitHub
        # pre-flight was skipped (API rate limit): without it, a private or
        # missing repo surfaces as a confusing generic 502.
        stderr = result.stderr.lower()

        if any(
            phrase in stderr
            for phrase in ("repository not found", "authentication", "could not read",
                           "not found", "access denied", "permission denied")
        ):
            raise HTTPException(
                status_code=404,
                detail="Repository not found on GitHub - it may be private or the URL is wrong.",
            )

        if any(
            phrase in stderr
            for phrase in ("could not resolve host", "unable to access",
                           "connection timed out", "network is unreachable")
        ):
            raise HTTPException(
                status_code=502,
                detail="Could not reach GitHub to clone the repository. Try again shortly.",
            )

        raise HTTPException(status_code=502, detail="Failed to clone the repository.")


def rmtree_force(path: str):
    """shutil.rmtree that clears the read-only flag git sets on object files (Windows)."""
    def on_error(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    shutil.rmtree(path, onerror=on_error)


def relativize(findings: list, root: str) -> list:
    """Rewrite absolute clone paths to repo-relative POSIX paths - never leak server paths."""
    out = []
    for f in findings:
        f = dict(f)
        f.pop("ignored", None)
        if "file" in f:
            f["file"] = os.path.relpath(f["file"], root).replace(os.sep, "/")
        out.append(f)
    return out


TEMP_PREFIX = "repo-scan-"
STALE_CLONE_AGE_S = 3600


def sweep_stale_clones():
    """Delete clones orphaned by an earlier process that died mid-scan.

    The finally block in /scan handles the normal path, but it cannot run if
    the process is killed outright - a crash, a container restart, or Render's
    free tier idling the service. Without this sweep those clones stay on disk
    forever. Scoped to our own prefix and to directories at least an hour old,
    so a scan running in a parallel worker is never touched.
    """
    temp_root = tempfile.gettempdir()
    cutoff = time.time() - STALE_CLONE_AGE_S
    try:
        entries = os.listdir(temp_root)
    except OSError:
        return

    for entry in entries:
        if not entry.startswith(TEMP_PREFIX):
            continue
        path = os.path.join(temp_root, entry)
        try:
            if os.path.isdir(path) and os.path.getmtime(path) < cutoff:
                rmtree_force(path)
        except OSError:
            # Best effort - a locked directory will be retried next startup.
            pass


def confidence_breakdown(findings: list) -> dict:
    """How many findings landed in each confidence tier, across all groups."""
    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        level = finding.get("confidence")
        if level in counts:
            counts[level] += 1
    return counts


@app.get("/")
def health():
    return {"status": "ok", "service": "repo-secret-scanner"}


@app.post("/scan")
def scan(request: ScanRequest):
    owner, repo = parse_github_url(request.repo_url)
    check_repo_public_and_size(owner, repo)

    tmpdir = tempfile.mkdtemp(prefix="repo-scan-")
    clone_dir = os.path.join(tmpdir, "repo")
    try:
        clone_repo(owner, repo, clone_dir)
        results = scan_repo(clone_dir)
        history = results["history"] if results["history"] is not None else []
        # The engine splits file findings by .gitignore status, which is a
        # pre-push check for local working copies. It doesn't apply here: a
        # clone contains only tracked files, and an ignore rule never untracks
        # something already committed. Anything the scan found in the clone is
        # public, so both groups report as exposed. (The CLI keeps the split.)
        exposed = relativize(results["exposed"] + results["gitignored"], clone_dir)

        return {
            "repo": f"{owner}/{repo}",
            "exposed": exposed,
            "history": history,
            "counts": {
                "exposed": len(exposed),
                "history": len(history),
            },
            "confidence_counts": confidence_breakdown(exposed + history),
            "history_depth": CLONE_DEPTH,
        }
    finally:
        rmtree_force(tmpdir)
