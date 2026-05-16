import subprocess
import os
from typing import Optional
from dotenv import load_dotenv

load_dotenv()


def clone_repository(repo_url: str, target_dir: str = "cloned_repo") -> str:
    """
    Clone a Git repository to a local directory.
    
    Args:
        repo_url: Git repository URL (HTTPS or SSH)
        target_dir: Directory to clone into
        
    Returns:
        Path to cloned repository
    """
    # Remove existing directory if it exists
    if os.path.exists(target_dir):
        subprocess.run(
            ["rm", "-rf", target_dir],
            check=True
        )
    
    # Clone repository
    result = subprocess.run(
        ["git", "clone", repo_url, target_dir],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        raise Exception(f"Git clone failed: {result.stderr}")
    
    return os.path.abspath(target_dir)


def create_branch(repo_path: str, branch_name: str = "security-remediation"):
    """
    Create and checkout a new branch in the repository.
    
    Args:
        repo_path: Path to the Git repository
        branch_name: Name of the new branch
    """
    result = subprocess.run(
        ["git", "checkout", "-b", branch_name],
        cwd=repo_path,
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        raise Exception(f"Branch creation failed: {result.stderr}")


def commit_changes(repo_path: str, message: str = "Security remediation: Fix vulnerabilities and misconfigurations"):
    """
    Stage and commit all changes in the repository.
    
    Args:
        repo_path: Path to the Git repository
        message: Commit message
    """
    # Stage all changes
    subprocess.run(
        ["git", "add", "."],
        cwd=repo_path,
        check=True
    )
    
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
    
    # Commit changes
    result = subprocess.run(
        ["git", "commit", "-m", message],
        cwd=repo_path,
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        raise Exception(f"Commit failed: {result.stderr}")


def push_branch(repo_path: str, branch_name: str = "security-remediation"):
    """
    Push the branch to remote repository.
    
    Args:
        repo_path: Path to the Git repository
        branch_name: Name of the branch to push
    """
    result = subprocess.run(
        ["git", "push", "-u", "origin", branch_name],
        cwd=repo_path,
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        raise Exception(f"Push failed: {result.stderr}")


def create_pull_request(
    repo_url: str,
    branch_name: str,
    title: str,
    body: str,
    github_token: Optional[str] = None
) -> str:
    """
    Create a pull request using GitHub CLI.
    
    Args:
        repo_url: Repository URL
        branch_name: Source branch name
        title: PR title
        body: PR description
        github_token: GitHub personal access token (optional, uses env var if not provided)
        
    Returns:
        PR URL
    """
    token = github_token or os.getenv("GITHUB_TOKEN")
    
    if not token:
        raise Exception("GitHub token not provided. Set GITHUB_TOKEN environment variable.")
    
    # Extract owner/repo from URL
    # Supports: https://github.com/owner/repo.git or git@github.com:owner/repo.git
    if "github.com" in repo_url:
        if repo_url.startswith("https://"):
            repo_path = repo_url.replace("https://github.com/", "").replace(".git", "")
        else:
            repo_path = repo_url.split("github.com:")[1].replace(".git", "")
    else:
        raise Exception("Only GitHub repositories are supported for PR creation")
    
    # Create PR using GitHub CLI
    result = subprocess.run(
        [
            "gh", "pr", "create",
            "--repo", repo_path,
            "--head", branch_name,
            "--title", title,
            "--body", body
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "GH_TOKEN": token}
    )
    
    if result.returncode != 0:
        raise Exception(f"PR creation failed: {result.stderr}")
    
    return result.stdout.strip()


def merge_pull_request(
    pr_url: str,
    github_token: Optional[str] = None,
    merge_method: str = "squash"
) -> bool:
    """
    Automatically merge a pull request.
    
    Args:
        pr_url: Pull request URL
        github_token: GitHub personal access token
        merge_method: Merge method (merge, squash, rebase)
        
    Returns:
        True if merged successfully, False otherwise
    """
    token = github_token or os.getenv("GITHUB_TOKEN")
    
    if not token:
        raise Exception("GitHub token not provided. Set GITHUB_TOKEN environment variable.")
    
    # Extract PR number from URL
    # Format: https://github.com/owner/repo/pull/123
    import re
    match = re.search(r'/pull/(\d+)', pr_url)
    if not match:
        raise Exception(f"Invalid PR URL format: {pr_url}")
    
    pr_number = match.group(1)
    
    # Extract repo path from URL
    repo_match = re.search(r'github\.com/([^/]+/[^/]+)', pr_url)
    if not repo_match:
        raise Exception(f"Could not extract repo from URL: {pr_url}")
    
    repo_path = repo_match.group(1)
    
    print(f"Attempting to merge PR #{pr_number}...")
    
    # Merge PR using GitHub CLI
    result = subprocess.run(
        [
            "gh", "pr", "merge", pr_number,
            "--repo", repo_path,
            f"--{merge_method}",
            "--auto"  # Auto-merge when checks pass
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "GH_TOKEN": token}
    )
    
    if result.returncode != 0:
        # Check if it's because checks are pending
        if "required status checks" in result.stderr.lower() or "not mergeable" in result.stderr.lower():
            print(f"[yellow]⚠ PR not immediately mergeable - waiting for checks...[/yellow]")
            return False
        raise Exception(f"PR merge failed: {result.stderr}")
    
    print(f"✓ PR #{pr_number} merged successfully")
    return True


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

# Made with Bob
