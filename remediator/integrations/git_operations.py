import base64
import glob
import json
import re
import subprocess
import os
import time
import urllib.error
import urllib.request
from typing import List, Optional
from dotenv import load_dotenv

load_dotenv()

# Allow-list of git URL forms: https://host/path, ssh://[user@]host/path, user@host:path.
# No whitespace or control characters, and the first character can never be '-'
# (which git would read as an option).
_REPO_URL_PATTERNS = (
    re.compile(r'^https://[A-Za-z0-9._~%:-]+(@[A-Za-z0-9.-]+)?(:\d+)?/[A-Za-z0-9._~%/+-]+$'),
    re.compile(r'^ssh://([A-Za-z0-9._-]+@)?[A-Za-z0-9.-]+(:\d+)?/[A-Za-z0-9._~%/+-]+$'),
    re.compile(r'^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[A-Za-z0-9._~%/+][A-Za-z0-9._~%/+-]*$'),
)
_MAX_REPO_URL_LENGTH = 2048
_CLONE_TIMEOUT_SECONDS = 600

# Remediation branch names are generated, but are checked before they reach git or the GitHub API
_BRANCH_NAME_PATTERN = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}\Z')
_GIT_PUSH_TIMEOUT_SECONDS = 300
_GITHUB_API_URL = "https://api.github.com"
_GITHUB_API_TIMEOUT_SECONDS = 60
_MAX_API_ERROR_LENGTH = 300

# owner/repo of a GitHub repository in the https, ssh:// and scp-like (git@github.com:owner/repo) forms
_GITHUB_REPO_PATTERNS = (
    re.compile(r'^https://(?:[^@/\s]+@)?github\.com(?::\d+)?/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+?)(?:\.git)?/*$', re.I),
    re.compile(r'^ssh://(?:[^@/\s]+@)?github\.com(?::\d+)?/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+?)(?:\.git)?/*$', re.I),
    re.compile(r'^[A-Za-z0-9._-]+@github\.com:([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+?)(?:\.git)?/*$', re.I),
)

# Credentials embedded in URLs (https://user:token@host/...)
_URL_CREDENTIALS = re.compile(r'(?<=//)[^/@\s]+@')


class UnsupportedRepositoryHost(Exception):
    """The repository is not hosted on GitHub, so no PR can be created."""


def scrub_secrets(text: str, *secrets: Optional[str]) -> str:
    """Remove tokens (and credentials embedded in URLs) from text that may be logged or shown."""
    text = str(text)
    for secret in secrets:
        if secret:
            text = text.replace(secret, "<redacted>")
    return _URL_CREDENTIALS.sub("", text)


def validate_branch_name(branch_name: str) -> str:
    """
    Check that a branch name is safe to pass to git and the GitHub API (allow-list, never starts with '-').

    Raises:
        ValueError: If the branch name is not accepted
    """
    if (not isinstance(branch_name, str) or not _BRANCH_NAME_PATTERN.match(branch_name)
            or '..' in branch_name or '//' in branch_name or branch_name.endswith(('/', '.', '.lock'))):
        raise ValueError("Invalid branch name")
    return branch_name


def parse_github_repo(repo_url: str) -> str:
    """
    Get "owner/repo" from a GitHub repository URL.

    Accepts https (trailing slash / .git allowed), ssh://git@github.com/owner/repo.git
    and git@github.com:owner/repo.git.

    Raises:
        UnsupportedRepositoryHost: If the URL is not a GitHub repository
    """
    repo_url = (repo_url or "").strip()
    for pattern in _GITHUB_REPO_PATTERNS:
        match = pattern.match(repo_url)
        if match:
            return f"{match.group(1)}/{match.group(2)}"
    raise UnsupportedRepositoryHost("Only GitHub repositories are supported for PR creation")


def _github_auth_env(repo_path: str, token: Optional[str]) -> dict:
    """
    Environment for a git command that authenticates to GitHub over https
    without putting the token in the remote URL or the process arguments.

    The token is sent as an http.extraHeader that is scoped to https://github.com/ only
    (so it is never sent to another host). ssh remotes rely on the machine's ssh config.
    """
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    if not token:
        return env

    remote = subprocess.run(
        ["git", "remote", "get-url", "origin"],
        cwd=repo_path,
        capture_output=True,
        text=True
    )
    if remote.returncode != 0 or not re.match(r'^https://(?:[^@/\s]+@)?github\.com(?::\d+)?/', remote.stdout.strip(), re.I):
        return env

    credentials = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    index = int(env.get("GIT_CONFIG_COUNT", "0") or 0)
    env["GIT_CONFIG_COUNT"] = str(index + 1)
    env[f"GIT_CONFIG_KEY_{index}"] = "http.https://github.com/.extraheader"
    env[f"GIT_CONFIG_VALUE_{index}"] = f"Authorization: Basic {credentials}"
    return env


# Clones left behind by crashed scans are removed once they are older than this,
# so a scan that is still running is never affected
STALE_CLONE_PATTERN = "security-remediation-*"
STALE_CLONE_MAX_AGE_SECONDS = 3600


def validate_repo_url(repo_url: str) -> str:
    """
    Check that a user-supplied repository URL is a plain https/ssh git URL.

    Args:
        repo_url: URL entered by the user

    Returns:
        The URL without surrounding whitespace

    Raises:
        ValueError: If the URL is not an accepted form
    """
    if not isinstance(repo_url, str):
        raise ValueError("Repository URL must be a string")

    repo_url = repo_url.strip()
    if (not repo_url or len(repo_url) > _MAX_REPO_URL_LENGTH or repo_url.startswith('-')
            or not any(p.match(repo_url) for p in _REPO_URL_PATTERNS)):
        raise ValueError("Invalid repository URL. Use an https:// or ssh git URL.")
    return repo_url


def clone_repository(repo_url: str, target_dir: str = "cloned_repo") -> str:
    """
    Clone a Git repository to a local directory.
    
    Args:
        repo_url: Git repository URL (HTTPS or SSH)
        target_dir: Directory to clone into
        
    Returns:
        Path to cloned repository

    Raises:
        ValueError: If repo_url is not an accepted git URL
    """
    repo_url = validate_repo_url(repo_url)

    # Remove existing directory if it exists
    if os.path.exists(target_dir):
        subprocess.run(
            ["rm", "-rf", target_dir],
            check=True
        )
    
    # Clone repository. '--' stops git from reading the URL or directory as an option,
    # and a missing credential must fail instead of waiting for a prompt.
    try:
        result = subprocess.run(
            ["git", "clone", "--", repo_url, target_dir],
            capture_output=True,
            text=True,
            timeout=_CLONE_TIMEOUT_SECONDS,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        )
    except subprocess.TimeoutExpired:
        raise Exception("Git clone timed out")
    
    if result.returncode != 0:
        # git echoes the URL in its errors, so never include credentials from it
        stderr = result.stderr.replace(repo_url, "<repository>")
        raise Exception(f"Git clone failed: {stderr}")
    
    return os.path.abspath(target_dir)


def get_default_branch(repo_path: str) -> str:
    """
    Get the default branch of a cloned repository (the base for a PR).

    Args:
        repo_path: Path to the cloned repository

    Returns:
        Branch name, e.g. "main"
    """
    result = subprocess.run(
        ["git", "symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
        cwd=repo_path,
        capture_output=True,
        text=True
    )
    if result.returncode == 0 and result.stdout.strip().startswith("origin/"):
        return result.stdout.strip()[len("origin/"):]

    # No origin/HEAD (e.g. an empty or unusual remote): fall back to the checked-out branch
    result = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=repo_path,
        capture_output=True,
        text=True
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise Exception("Could not determine the default branch")
    return result.stdout.strip()


def cleanup_stale_clones(base_dir: str = ".", max_age_seconds: int = STALE_CLONE_MAX_AGE_SECONDS):
    """
    Remove clone directories left behind by earlier scans.

    Args:
        base_dir: Directory that holds the clones
        max_age_seconds: Only directories older than this are removed
    """
    cutoff = time.time() - max_age_seconds
    for path in glob.glob(os.path.join(base_dir, STALE_CLONE_PATTERN)):
        if os.path.isdir(path) and not os.path.islink(path) and os.path.getmtime(path) < cutoff:
            cleanup_cloned_repo(path)


def cleanup_cloned_repo(target_dir: str = "cloned_repo"):
    """
    Clean up the cloned repository directory.
    
    Args:
        target_dir: Directory to remove
    """
    import shutil
    
    if os.path.exists(target_dir):
        try:
            shutil.rmtree(target_dir)
            print(f"✓ Cleaned up {target_dir}")
        except Exception as e:
            print(f"Warning: Could not clean up {target_dir}: {e}")



def create_branch(repo_path: str, branch_name: str = "security-remediation"):
    """
    Create and checkout a new branch in the repository.
    
    Args:
        repo_path: Path to the Git repository
        branch_name: Name of the new branch
    """
    validate_branch_name(branch_name)
    result = subprocess.run(
        ["git", "checkout", "-b", branch_name],
        cwd=repo_path,
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        raise Exception(f"Branch creation failed: {result.stderr}")


def commit_changes(
    repo_path: str,
    message: str = "Security remediation: Fix vulnerabilities and misconfigurations",
    paths: Optional[List[str]] = None
):
    """
    Stage and commit changes in the repository.
    
    Args:
        repo_path: Path to the Git repository
        message: Commit message
        paths: Repo-relative files to commit. Only these are staged and committed.
               If omitted, all changes are staged (legacy behaviour).
    """
    if paths is None:
        # Stage all changes
        subprocess.run(
            ["git", "add", "."],
            cwd=repo_path,
            check=True
        )
        pathspec = []
    else:
        if not paths:
            raise Exception("No files to commit")
        for path in paths:
            if (not isinstance(path, str) or not path or os.path.isabs(path)
                    or '..' in path.replace('\\', '/').split('/')):
                raise ValueError("Invalid file path")
        # '--' keeps a file name from being read as an option
        result = subprocess.run(
            ["git", "add", "--", *paths],
            cwd=repo_path,
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            raise Exception(f"Staging failed: {result.stderr}")
        pathspec = ["--", *paths]
    
    # Configure git user if not set
    subprocess.run(
        ["git", "config", "user.email", "audesec-bot@example.com"],
        cwd=repo_path,
        capture_output=True
    )
    
    subprocess.run(
        ["git", "config", "user.name", "AudeSec Bot"],
        cwd=repo_path,
        capture_output=True
    )
    
    # Commit changes (only the given paths when a list was passed)
    result = subprocess.run(
        ["git", "commit", "-m", message, *pathspec],
        cwd=repo_path,
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        raise Exception(f"Commit failed: {result.stderr}")


def push_branch(repo_path: str, branch_name: str = "security-remediation", github_token: Optional[str] = None):
    """
    Push the branch to remote repository.

    For an https GitHub remote the token (argument, or GITHUB_TOKEN) is passed to git
    through the environment only; it is never part of the URL or the arguments, and it
    is removed from any error text.
    
    Args:
        repo_path: Path to the Git repository
        branch_name: Name of the branch to push
        github_token: GitHub token (optional, uses GITHUB_TOKEN if not provided)
    """
    validate_branch_name(branch_name)
    token = github_token or os.getenv("GITHUB_TOKEN")
    
    try:
        result = subprocess.run(
            ["git", "push", "-u", "origin", branch_name],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=_GIT_PUSH_TIMEOUT_SECONDS,
            env=_github_auth_env(repo_path, token)
        )
    except subprocess.TimeoutExpired:
        raise Exception("Push timed out")
    
    if result.returncode != 0:
        raise Exception(f"Push failed: {scrub_secrets(result.stderr, token)}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: the Authorization header must only ever go to api.github.com."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_GITHUB_OPENER = urllib.request.build_opener(_NoRedirect)


def _github_api(method: str, path: str, token: str, payload: Optional[dict] = None):
    """
    Call the GitHub REST API (https://api.github.com, certificates verified).

    The token is only sent in the Authorization header. Redirects are not followed.

    Returns:
        (status code, decoded JSON body or {})

    Raises:
        Exception: On network errors and timeouts (message never contains the token)
    """
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        f"{_GITHUB_API_URL}{path}",
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "audesec-remediator",
            **({"Content-Type": "application/json"} if data is not None else {}),
        }
    )

    try:
        with _GITHUB_OPENER.open(request, timeout=_GITHUB_API_TIMEOUT_SECONDS) as response:
            status, raw = response.status, response.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    except (urllib.error.URLError, TimeoutError) as e:
        raise Exception(f"Could not reach GitHub: {scrub_secrets(getattr(e, 'reason', e), token)}")

    try:
        body = json.loads(raw) if raw else {}
    except ValueError:
        body = {}
    return status, body if isinstance(body, dict) else {}


def _github_error(body: dict, token: str) -> str:
    """Short, token-free text of a GitHub API error (message plus any validation details)."""
    parts = [str(body.get("message") or "no details")]
    for error in body.get("errors") or []:
        if isinstance(error, dict):
            parts.append(str(error.get("message") or error.get("code") or ""))
        else:
            parts.append(str(error))
    return scrub_secrets("; ".join(p for p in parts if p), token)[:_MAX_API_ERROR_LENGTH]


def create_pull_request(
    repo_url: str,
    branch_name: str,
    title: str,
    body: str,
    github_token: Optional[str] = None,
    base: Optional[str] = None
) -> str:
    """
    Create a pull request through the GitHub REST API (no GitHub CLI needed).
    
    Args:
        repo_url: Repository URL (https, ssh:// or git@github.com:owner/repo forms)
        branch_name: Source branch name (must already be pushed)
        title: PR title
        body: PR description
        github_token: GitHub personal access token (optional, uses env var if not provided)
        base: Branch the PR targets (optional, the repository's default branch is used)
        
    Returns:
        PR URL

    Raises:
        UnsupportedRepositoryHost: If the repository is not on GitHub
    """
    token = github_token or os.getenv("GITHUB_TOKEN")
    
    if not token:
        raise Exception("GitHub token not provided. Set GITHUB_TOKEN environment variable.")
    
    repo_path = parse_github_repo(repo_url)
    validate_branch_name(branch_name)
    if base:
        validate_branch_name(base)
    else:
        status, repo = _github_api("GET", f"/repos/{repo_path}", token)
        if status != 200 or not repo.get("default_branch"):
            raise Exception(f"Could not read the default branch ({status}): {_github_error(repo, token)}")
        base = validate_branch_name(repo["default_branch"])

    status, pull = _github_api("POST", f"/repos/{repo_path}/pulls", token, {
        "title": title,
        "head": branch_name,
        "base": base,
        "body": body,
    })
    if status != 201:
        raise Exception(f"PR creation failed ({status}): {_github_error(pull, token)}")

    pr_url = pull.get("html_url")
    if not isinstance(pr_url, str) or not pr_url.startswith("https://"):
        raise Exception("PR was created but GitHub returned no URL")
    return pr_url


def merge_pull_request(
    pr_url: str,
    github_token: Optional[str] = None,
    merge_method: str = "squash"
) -> bool:
    """
    Merge a pull request through the GitHub REST API (no GitHub CLI needed).
    
    Args:
        pr_url: Pull request URL
        github_token: GitHub personal access token
        merge_method: Merge method (merge, squash, rebase)
        
    Returns:
        True if merged, False if the PR cannot be merged right now (checks pending, conflicts)
    """
    token = github_token or os.getenv("GITHUB_TOKEN")
    
    if not token:
        raise Exception("GitHub token not provided. Set GITHUB_TOKEN environment variable.")

    if merge_method not in ("merge", "squash", "rebase"):
        raise ValueError("Invalid merge method")
    
    # Format: https://github.com/owner/repo/pull/123
    match = re.match(r'^https://github\.com/([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)/pull/(\d+)/*$', (pr_url or "").strip())
    if not match:
        raise Exception("Invalid PR URL format")
    repo_path, pr_number = match.groups()
    
    status, result = _github_api("PUT", f"/repos/{repo_path}/pulls/{pr_number}/merge", token,
                                 {"merge_method": merge_method})
    if status == 200 and result.get("merged"):
        print(f"✓ PR #{pr_number} merged successfully")
        return True
    if status in (405, 409):
        # Not mergeable yet: required checks pending, conflicts, or the head changed
        print(f"⚠ PR #{pr_number} is not mergeable yet: {_github_error(result, token)}")
        return False
    raise Exception(f"PR merge failed ({status}): {_github_error(result, token)}")


def pull_latest_changes(repo_path: str, branch: str = "main"):
    """
    Pull latest changes from remote repository.
    
    Args:
        repo_path: Path to local repository
        branch: Branch to pull from (default: main)
    """
    # Checkout main/master branch
    subprocess.run(
        ["git", "checkout", branch],
        cwd=repo_path,
        capture_output=True,
        check=False  # Don't fail if branch doesn't exist
    )
    
    # Try master if main doesn't exist
    if branch == "main":
        result = subprocess.run(
            ["git", "rev-parse", "--verify", "main"],
            cwd=repo_path,
            capture_output=True
        )
        if result.returncode != 0:
            branch = "master"
            subprocess.run(
                ["git", "checkout", branch],
                cwd=repo_path,
                check=True
            )
    
    # Pull latest changes
    result = subprocess.run(
        ["git", "pull", "origin", branch],
        cwd=repo_path,
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        raise Exception(f"Git pull failed: {result.stderr}")
    
    print(f"✓ Pulled latest changes from {branch}")
    return branch


def generate_pr_body(
    original_cves: int,
    fixed_cves: int,
    original_misconfigs: int,
    fixed_misconfigs: int,
    findings_summary: list
) -> str:
    """
    Generate a detailed PR description.
    
    Args:
        original_cves: Number of CVEs before remediation
        fixed_cves: Number of CVEs after remediation
        original_misconfigs: Number of misconfigurations before
        fixed_misconfigs: Number of misconfigurations after
        findings_summary: List of critical findings addressed
        
    Returns:
        Formatted PR body
    """
    cve_improvement = original_cves - fixed_cves
    misconfig_improvement = original_misconfigs - fixed_misconfigs
    
    body = f"""## 🔒 Automated Security Remediation

This PR contains automated security fixes generated by AudeSec-POC.

### 📊 Security Improvements

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| CVEs | {original_cves} | {fixed_cves} | ✅ {cve_improvement} fixed |
| Misconfigurations | {original_misconfigs} | {fixed_misconfigs} | ✅ {misconfig_improvement} fixed |

### 🎯 Critical Issues Addressed

"""
    
    for i, finding in enumerate(findings_summary[:10], 1):
        severity = finding.get("severity", "UNKNOWN")
        finding_id = finding.get("id", "N/A")
        finding_type = finding.get("type", "UNKNOWN")
        
        body += f"{i}. **[{severity}]** {finding_type}: `{finding_id}`\n"
    
    if len(findings_summary) > 10:
        body += f"\n_...and {len(findings_summary) - 10} more issues_\n"
    
    body += """
### 🔧 Changes Made

- ✅ Updated vulnerable dependencies to secure versions
- ✅ Fixed Kubernetes security misconfigurations
- ✅ Applied security best practices
- ✅ Validated all changes

### ⚠️ Review Checklist

- [ ] Review dependency version changes
- [ ] Verify Kubernetes configuration changes
- [ ] Test application functionality
- [ ] Check for breaking changes

### 🤖 Automated by AudeSec-POC

This PR was automatically generated. Please review carefully before merging.
"""
    
    return body


_METRIC_LABELS = (
    ("kubernetes", "Kubernetes misconfigurations"),
    ("cve", "Container CVEs"),
    ("sast", "Code (SAST) issues"),
    ("secrets", "Hardcoded secrets"),
    ("total", "**Total**"),
)
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_MAX_PR_FINDINGS = 15


def _md_text(value) -> str:
    """Make a scanner-provided value safe to put in a markdown table or code span."""
    return re.sub(r'[`|\r\n<>]', ' ', str(value if value is not None else "N/A")).strip()[:120]


def generate_remediation_pr_body(
    files_updated: List[str],
    metrics: dict,
    findings: Optional[List[dict]] = None,
    jira_keys: Optional[List[str]] = None
) -> str:
    """
    Generate a PR description from what a remediation run really changed.

    Args:
        files_updated: Repo-relative files that were changed
        metrics: Per-category before/after numbers, e.g. {"cve": {"before": 5, "after": 2, ...}}
        findings: Findings of the scan (only those located in a changed file are listed)
        jira_keys: JIRA tickets created for the scan
        
    Returns:
        Formatted PR body
    """
    files_updated = list(files_updated or [])
    body = "## Automated Security Remediation\n\n"
    body += "This PR contains automated security fixes generated by AudeSec-POC.\n\n"

    body += f"### Files changed ({len(files_updated)})\n\n"
    for path in files_updated:
        body += f"- `{_md_text(path)}`\n"

    rows = [(label, metrics[key]) for key, label in _METRIC_LABELS
            if isinstance(metrics.get(key), dict) and 'before' in metrics[key]]
    if rows:
        body += "\n### Before / after (re-scan of the fixed repository)\n\n"
        body += "| Category | Before | After | Fixed |\n|----------|--------|-------|-------|\n"
        for label, m in rows:
            body += f"| {label} | {m['before']} | {m['after']} | {m['fixed']} |\n"

    changed = set(files_updated)
    related = [f for f in (findings or []) if f.get("file") in changed]
    related.sort(key=lambda f: _SEVERITY_ORDER.get(str(f.get("severity")).upper(), 4))
    if related:
        body += "\n### Findings in the changed files\n\n"
        for i, finding in enumerate(related[:_MAX_PR_FINDINGS], 1):
            body += (f"{i}. **[{_md_text(finding.get('severity', 'UNKNOWN'))}]** "
                     f"{_md_text(finding.get('type', 'UNKNOWN'))}: `{_md_text(finding.get('id'))}` "
                     f"in `{_md_text(finding.get('file'))}`\n")
        if len(related) > _MAX_PR_FINDINGS:
            body += f"\n_...and {len(related) - _MAX_PR_FINDINGS} more_\n"

    if jira_keys:
        body += "\n### JIRA tickets\n\n"
        body += ", ".join(f"`{_md_text(key)}`" for key in jira_keys) + "\n"

    body += """
### Review checklist

- [ ] Review every changed file listed above
- [ ] Test application functionality and build the images
- [ ] Check for breaking changes (dependency, base image and manifest changes)
- [ ] Remaining findings are not fixed by this PR

This PR was generated automatically. Please review carefully before merging.
"""
    return body
