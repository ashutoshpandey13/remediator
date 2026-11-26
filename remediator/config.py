import os
import random
import string
from typing import Optional
from dataclasses import dataclass


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


def find_files_in_repo(repo_path: str, config: RepoConfig) -> dict:
    """
    Find required files in the cloned repository.
    
    Args:
        repo_path: Path to cloned repository
        config: Repository configuration
        
    Returns:
        Dictionary with file paths
    """
    import glob
    
    files = {
        "deployment_yaml": None,
        "package_json": None,
        "dockerfile": None
    }
    
    # Search for deployment.yaml
    deployment_patterns = [
        os.path.join(repo_path, config.deployment_yaml_path),
        os.path.join(repo_path, "**", "deployment.yaml"),
        os.path.join(repo_path, "**", "deployment.yml"),
        os.path.join(repo_path, "k8s", "*.yaml"),
        os.path.join(repo_path, "kubernetes", "*.yaml")
    ]
    
    for pattern in deployment_patterns:
        matches = glob.glob(pattern, recursive=True)
        if matches:
            files["deployment_yaml"] = matches[0]
            break
    
    # Search for package.json
    package_patterns = [
        os.path.join(repo_path, config.package_json_path),
        os.path.join(repo_path, "**", "package.json")
    ]
    
    for pattern in package_patterns:
        matches = glob.glob(pattern, recursive=True)
        if matches:
            # Exclude node_modules
            matches = [m for m in matches if "node_modules" not in m]
            if matches:
                files["package_json"] = matches[0]
                break
    
    # Search for Dockerfile
    dockerfile_patterns = [
        os.path.join(repo_path, config.dockerfile_path),
        os.path.join(repo_path, "**", "Dockerfile")
    ]
    
    for pattern in dockerfile_patterns:
        matches = glob.glob(pattern, recursive=True)
        if matches:
            files["dockerfile"] = matches[0]
            break
    
    return files


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
    
    # Get optional paths from environment
    deployment_file = os.getenv("DEPLOYMENT_YAML_PATH", "deployment.yaml")
    package_json_file = os.getenv("PACKAGE_JSON_PATH", "package.json")
    dockerfile = os.getenv("DOCKERFILE_PATH", "Dockerfile")
    
    # Generate unique branch name
    branch = generate_unique_branch_name()
    
    # Generate image name
    image_name = f"{repo_name}-scan"
    
    return {
        "repo_url": repo_url,
        "repo_name": repo_name,
        "deployment_file": deployment_file,
        "package_json_file": package_json_file,
        "dockerfile": dockerfile,
        "branch": branch,
        "image_name": image_name
    }
