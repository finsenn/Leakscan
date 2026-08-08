"""FastAPI backend for the repo secret scanner.

One endpoint: POST /scan. Takes a public github.com repo URL, shallow-clones
it to a temp dir, runs the scanning engine, returns grouped masked findings,
and always deletes the clone.
"""

import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import urllib.error
import urllib.request

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

app = FastAPI(title="Repo Secret Scanner", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # demo app, no credentials; tighten to the Vercel domain later
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
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
        raise HTTPException(status_code=504, detail="Cloning the repository timed out.")
    if result.returncode != 0:
        # stderr may mention auth for private repos; don't echo it back verbatim
        if "Authentication" in result.stderr or "could not read" in result.stderr:
            raise HTTPException(
                status_code=404,
                detail="Repository not found on GitHub - it may be private or the URL is wrong.",
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
            "history_depth": CLONE_DEPTH,
        }
    finally:
        rmtree_force(tmpdir)
