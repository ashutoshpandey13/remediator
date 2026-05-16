# AudeSec-POC - Automated Security Remediation System

An intelligent security remediation system that automatically scans, detects, fixes, and validates security vulnerabilities in Kubernetes deployments and container images.

## 🚀 New Features

### Git Repository Integration
- **Clone any Git repository** for security scanning
- **Automatic PR creation** with remediated code
- **Branch management** for security fixes
- **Comprehensive security reports** in PR descriptions

## 📋 Overview

AudeSec-POC automates the entire security remediation workflow:

1. **Clone** - Clone target Git repository
2. **Scan** - Detect vulnerabilities and misconfigurations
3. **Remediate** - AI-powered automatic fixes
4. **Validate** - Ensure fixes are correct
5. **PR** - Create pull request with changes
6. **Rebuild** - Build and test fixed container
7. **Re-scan** - Verify security improvements

## 🔧 Prerequisites

### Required Tools
- Python 3.8+
- Docker
- Trivy (security scanner)
- Git
- GitHub CLI (`gh`) - for PR creation

### Install Dependencies

```bash
# Install Python dependencies
pip install -r requirements.txt

# Install Trivy
# macOS
brew install trivy

# Linux
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# Install GitHub CLI
# macOS
brew install gh

# Linux
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt update
sudo apt install gh
```

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Required: OpenAI API Key for AI remediation
OPENAI_API_KEY=your_openai_api_key

# Required: GitHub Token for PR creation
GITHUB_TOKEN=your_github_personal_access_token

# Optional: JIRA Integration
JIRA_URL=https://your-domain.atlassian.net
JIRA_EMAIL=your-email@example.com
JIRA_API_TOKEN=your_jira_api_token
JIRA_PROJECT=PROJECT_KEY

# Optional: Repository Configuration
REPO_URL=https://github.com/owner/repo.git
DEPLOYMENT_YAML_PATH=deployment.yaml
PACKAGE_JSON_PATH=package.json
DOCKERFILE_PATH=Dockerfile
BRANCH_NAME=security-remediation
```

### GitHub Token Setup

1. Go to GitHub Settings → Developer settings → Personal access tokens
2. Generate new token with these scopes:
   - `repo` (Full control of private repositories)
   - `workflow` (Update GitHub Action workflows)
3. Copy token to `.env` file

### Authenticate GitHub CLI

```bash
gh auth login
```

## 🎯 Usage

### Basic Usage (Interactive)

```bash
python app.py
```

The system will prompt you for the Git repository URL.

### Using Environment Variables

```bash
# Set repository URL
export REPO_URL=https://github.com/your-org/your-repo.git

# Run the scanner
python app.py
```

### Custom File Paths

If your repository has non-standard file locations:

```bash
export DEPLOYMENT_YAML_PATH=k8s/production/deployment.yaml
export PACKAGE_JSON_PATH=backend/package.json
export DOCKERFILE_PATH=docker/Dockerfile

python app.py
```

## 📊 Workflow Steps

### Step 1: Repository Configuration
- Accepts Git repository URL (HTTPS or SSH)
- Configures file paths and branch name

### Step 2: Clone Repository
- Clones repository to `cloned_repo/` directory
- Removes existing clone if present

### Step 3: File Discovery
- Automatically locates:
  - Kubernetes deployment YAML
  - package.json (Node.js dependencies)
  - Dockerfile

### Step 4: Kubernetes Security Scan
- Scans K8s configs with Trivy
- Detects misconfigurations
- Categorizes by severity (CRITICAL, HIGH, MEDIUM, LOW)

### Step 5: Container Image CVE Scan
- Builds Docker image from repository
- Scans for CVEs using Trivy
- Identifies vulnerable packages

### Step 6: Unified Findings
- Combines K8s and CVE findings
- Normalizes severity levels
- Prioritizes critical issues

### Step 7: JIRA Ticket Creation
- Creates tickets for HIGH/CRITICAL issues
- Includes detailed vulnerability information
- Links to remediation PR (optional)

### Step 8: AI-Powered Remediation
- Uses OpenAI GPT-4 to generate fixes
- Updates Kubernetes configurations
- Upgrades vulnerable dependencies
- Maintains application functionality

### Step 9: Apply Remediation
- Writes fixed files back to repository
- Updates deployment.yaml
- Updates package.json

### Step 10: Validation
- Validates YAML syntax
- Validates JSON syntax
- Ensures files are parseable

### Step 11: Git Branch Creation
- Creates new branch (default: `security-remediation`)
- Commits all changes
- Includes detailed commit message

### Step 12: Pull Request Creation
- Pushes branch to remote
- Creates PR with:
  - Security improvement metrics
  - List of fixed vulnerabilities
  - Review checklist
- Returns PR URL

### Step 13: Rebuild Container
- Builds new Docker image with fixes
- Tags as `remediated-{repo-name}`

### Step 14: Re-scan Fixed Assets
- Re-scans Kubernetes config
- Re-scans container image
- Compares before/after metrics

### Step 15: Security Improvement Summary
- Shows CVE reduction
- Shows misconfiguration reduction
- Calculates improvement percentage

## 📁 Project Structure

```
audesec-poc/
├── app.py                      # Main application (new workflow)
├── config.py                   # Configuration management
├── requirements.txt            # Python dependencies
├── .env                        # Environment variables (create this)
├── agents/
│   ├── scanner.py             # Kubernetes config scanner
│   ├── image_scanner.py       # Container image scanner
│   ├── findings.py            # Findings normalization
│   ├── jira_agent.py          # JIRA integration
│   ├── remediation.py         # AI remediation engine
│   ├── validator.py           # File validation
│   └── git_operations.py      # Git & PR operations (new)
├── reports/                    # Scan reports (auto-generated)
│   ├── k8s_scan.json
│   └── image_scan.json
└── cloned_repo/               # Cloned repository (auto-generated)
```

## 🔒 Security Best Practices

### Secrets Management
- Never commit `.env` file
- Use environment variables for sensitive data
- Rotate API tokens regularly

### Repository Access
- Use read-only tokens when possible
- Limit token scopes to minimum required
- Use SSH keys for private repositories

### PR Review
- Always review AI-generated changes
- Test in staging environment first
- Verify no breaking changes introduced

## 🐛 Troubleshooting

### "Git clone failed"
- Check repository URL is correct
- Verify you have access to the repository
- For private repos, ensure SSH key or token is configured

### "PR creation failed"
- Verify `GITHUB_TOKEN` is set and valid
- Check token has `repo` scope
- Ensure GitHub CLI is authenticated: `gh auth status`

### "Docker build failed"
- Verify Dockerfile exists and is valid
- Check Docker daemon is running
- Ensure all build dependencies are available

### "Trivy scan failed"
- Update Trivy: `trivy --version` and upgrade if needed
- Check internet connectivity (Trivy downloads vulnerability DB)
- Verify file paths are correct

### "OpenAI API error"
- Check `OPENAI_API_KEY` is valid
- Verify you have API credits
- Check rate limits

## 📈 Example Output

```
═══ STEP 1: Repository Configuration ═══
✓ Repository: https://github.com/example/vulnerable-app.git

═══ STEP 2: Cloning Repository ═══
✓ Cloned to: /path/to/cloned_repo

═══ STEP 3: Locating Files ═══
✓ Deployment YAML: cloned_repo/deployment.yaml
✓ Package JSON: cloned_repo/package.json
✓ Dockerfile: cloned_repo/Dockerfile

═══ STEP 4: Kubernetes Security Scan ═══
Found 5 Kubernetes misconfigurations:
  [HIGH] Container should not run as root
  [MEDIUM] CPU limits not set
  [MEDIUM] Memory limits not set
  ...

═══ STEP 15: Security Improvement Summary ═══
Metric                    Before     After      Improvement    
────────────────────────────────────────────────────────────
CVEs                      47         12         35             
Misconfigurations         5          1          4              

✓ Overall improvement: 85.4%

═══ REMEDIATION COMPLETE ═══
Repository: https://github.com/example/vulnerable-app.git
Branch: security-remediation
Pull Request: https://github.com/example/vulnerable-app/pull/123
```

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

This project is for proof-of-concept purposes.

## 🔗 Related Tools

- [Trivy](https://github.com/aquasecurity/trivy) - Vulnerability scanner
- [GitHub CLI](https://cli.github.com/) - GitHub command line tool
- [OpenAI API](https://openai.com/api/) - AI-powered remediation

## 📞 Support

For issues and questions:
- Open an issue on GitHub
- Check existing documentation
- Review troubleshooting section

---

**Note**: This is a proof-of-concept tool. Always review AI-generated changes before merging to production.