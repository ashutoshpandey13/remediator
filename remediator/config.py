import os
import re
import secrets
import string

import yaml


def generate_unique_branch_name(base_name: str = "security-remediation") -> str:
    """
    Generate a unique branch name with random suffix.
    
    Args:
        base_name: Base branch name
        
    Returns:
        Branch name with random suffix (e.g., security-remediation-a3f9x2)
    """
    # Generate 6 random alphanumeric characters
    suffix = ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(6))
    return f"{base_name}-{suffix}"


# Directories that never contain the repository's own assets
SKIPPED_DIRS = ("node_modules", ".git", "vendor")

# K8s manifests are small; anything bigger is data, not a manifest
MAX_MANIFEST_BYTES = 1024 * 1024


def _is_dockerfile(name: str) -> bool:
    return name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile")


def is_k8s_manifest(path: str) -> bool:
    """A K8s manifest is a YAML document with both `apiVersion` and `kind`."""
    try:
        if os.path.getsize(path) > MAX_MANIFEST_BYTES:
            return False
        with open(path, "r", encoding="utf-8") as f:
            for doc in yaml.safe_load_all(f):
                if isinstance(doc, dict) and "apiVersion" in doc and "kind" in doc:
                    return True
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        # Unreadable files and templates that are not valid YAML (e.g. Helm) are not scanned
        return False
    return False


def discover_repo_files(repo_path: str) -> dict:
    """
    Recursively find the scannable files in a cloned repository.

    Kubernetes manifests are detected by content, not by file name.
    Symlinks are ignored so a repository cannot point the scan outside itself.

    Args:
        repo_path: Path to cloned repository

    Returns:
        {"k8s_manifests": [...], "dockerfiles": [...], "package_jsons": [...]}
        Each list holds sorted repo-relative paths.
    """
    found = {"k8s_manifests": [], "dockerfiles": [], "package_jsons": []}

    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in SKIPPED_DIRS]
        for name in filenames:
            full_path = os.path.join(dirpath, name)
            if os.path.islink(full_path):
                continue

            rel_path = os.path.relpath(full_path, repo_path)
            if name == "package.json":
                found["package_jsons"].append(rel_path)
            elif _is_dockerfile(name):
                found["dockerfiles"].append(rel_path)
            elif name.endswith((".yaml", ".yml")) and is_k8s_manifest(full_path):
                found["k8s_manifests"].append(rel_path)

    for paths in found.values():
        paths.sort()
    return found


def get_repository_config(repo_url: str) -> dict:
    """
    Get repository configuration for web UI.
    
    Args:
        repo_url: Git repository URL
        
    Returns:
        Dictionary with configuration details
    """
    # Extract repo name from URL
    repo_name = repo_url.rstrip('/').split('/')[-1].replace('.git', '')
    
    # Generate unique branch name
    branch = generate_unique_branch_name()
    
    # Each scan clones into its own directory, separate from the branch name
    clone_dir = generate_unique_branch_name("security-remediation-clone")
    
    # Image base name: valid docker name, unique per scan so concurrent scans never collide
    safe_name = re.sub(r'[^a-z0-9_.-]', '-', repo_name.lower()).strip('-.')[:40] or 'repo'
    image_name = generate_unique_branch_name(f"{safe_name}-scan")
    
    return {
        "repo_url": repo_url,
        "repo_name": repo_name,
        "branch": branch,
        "clone_dir": clone_dir,
        "image_name": image_name
    }
