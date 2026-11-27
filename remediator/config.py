import os
import random
import re
import string
from typing import Optional
from dataclasses import dataclass

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
    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{base_name}-{suffix}"


@dataclass
class RepoConfig:
    """Configuration for repository scanning."""
    repo_url: str
    deployment_yaml_path: str = "deployment.yaml"
    package_json_path: str = "package.json"
    dockerfile_path: str = "Dockerfile"
    branch_name: str = None  # Will be generated if not provided
    
    def __post_init__(self):
        """Generate unique branch name if not provided."""
        if self.branch_name is None:
            self.branch_name = generate_unique_branch_name()
    

def get_repo_config_from_input() -> RepoConfig:
    """
    Get repository configuration from user input or environment variables.
    
    Returns:
        RepoConfig object with repository details
    """
    # Try to get from environment variable first
    repo_url = os.getenv("REPO_URL")
    
    if not repo_url:
        print("\n" + "="*60)
        print("🔒 AudeSec-POC - Automated Security Remediation")
        print("="*60 + "\n")
        
        repo_url = input("Enter Git repository URL: ").strip()
        
        if not repo_url:
            raise ValueError("Repository URL is required")
    
    # Optional: Get custom paths
    deployment_path = os.getenv("DEPLOYMENT_YAML_PATH", "deployment.yaml")
    package_path = os.getenv("PACKAGE_JSON_PATH", "package.json")
    dockerfile_path = os.getenv("DOCKERFILE_PATH", "Dockerfile")
    
    # Generate unique branch name (or use env var if provided)
    branch_name = os.getenv("BRANCH_NAME")
    if not branch_name:
        branch_name = generate_unique_branch_name()
    
    return RepoConfig(
        repo_url=repo_url,
        deployment_yaml_path=deployment_path,
        package_json_path=package_path,
        dockerfile_path=dockerfile_path,
        branch_name=branch_name
    )


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


def find_files_in_repo(repo_path: str, config: RepoConfig = None) -> dict:
    """
    Find the first file of each type in the cloned repository.

    Kept for the CLI, which handles a single file of each type.
    The web flow uses discover_repo_files().

    Args:
        repo_path: Path to cloned repository
        config: Unused, kept for compatibility

    Returns:
        Dictionary with absolute file paths (None when not found)
    """
    found = discover_repo_files(repo_path)

    def first(rel_paths):
        return os.path.join(repo_path, rel_paths[0]) if rel_paths else None

    return {
        "deployment_yaml": first(found["k8s_manifests"]),
        "package_json": first(found["package_jsons"]),
        "dockerfile": first(found["dockerfiles"])
    }


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
