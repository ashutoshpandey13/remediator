# AudeSec-POC Setup and Running Guide

## 🚀 Quick Start Guide

Follow these steps to set up and run the project.

---

## Step 1: Install System Dependencies

### macOS

```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install required tools
brew install python@3.11
brew install docker
brew install trivy
brew install gh
brew install git
```

### Linux (Ubuntu/Debian)

```bash
# Update package list
sudo apt update

# Install Python 3.11
sudo apt install python3.11 python3.11-venv python3-pip

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
newgrp docker

# Install Trivy
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt update
sudo apt install trivy

# Install GitHub CLI
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt update
sudo apt install gh
```

---

## Step 2: Verify Installations

```bash
# Check Python version (should be 3.8+)
python3 --version

# Check Docker
docker --version
docker ps

# Check Trivy
trivy --version

# Check GitHub CLI
gh --version

# Check Git
git --version
```

---

## Step 3: Clone the Project

```bash
cd ~/
git clone <your-audesec-poc-repo-url>
cd audesec-poc
```

---

## Step 4: Install Python Dependencies

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate

# On Windows:
# venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### If requirements.txt is missing, install manually:

```bash
pip install rich python-dotenv openai jira pyyaml
```

---

## Step 5: Set Up Environment Variables

### Create .env file

```bash
# Copy the example file
cp .env.example .env

# Edit the .env file
nano .env  # or use your preferred editor
```

### Required Configuration in .env:

```bash
# REQUIRED: OpenAI API Key
OPENAI_API_KEY=sk-your-actual-openai-api-key-here

# REQUIRED: GitHub Personal Access Token
GITHUB_TOKEN=ghp_your-actual-github-token-here

# OPTIONAL: JIRA Configuration (skip if not using JIRA)
# JIRA_URL=https://your-domain.atlassian.net
# JIRA_EMAIL=your-email@example.com
# JIRA_API_TOKEN=your-jira-api-token
# JIRA_PROJECT=PROJ

# OPTIONAL: Repository Configuration (can provide interactively)
# REPO_URL=https://github.com/owner/repo.git
# DEPLOYMENT_YAML_PATH=deployment.yaml
# PACKAGE_JSON_PATH=package.json
# DOCKERFILE_PATH=Dockerfile
# BRANCH_NAME=security-remediation
```

---

## Step 6: Get Required API Keys

### A. OpenAI API Key

1. Go to https://platform.openai.com/api-keys
2. Sign in or create an account
3. Click "Create new secret key"
4. Copy the key (starts with `sk-`)
5. Add to `.env` file: `OPENAI_API_KEY=sk-...`

### B. GitHub Personal Access Token

1. Go to https://github.com/settings/tokens
2. Click "Generate new token" → "Generate new token (classic)"
3. Give it a name: "AudeSec-POC"
4. Select scopes:
   - ✅ `repo` (Full control of private repositories)
   - ✅ `workflow` (Update GitHub Action workflows)
5. Click "Generate token"
6. Copy the token (starts with `ghp_`)
7. Add to `.env` file: `GITHUB_TOKEN=ghp_...`

### C. Authenticate GitHub CLI

```bash
gh auth login
# Follow the prompts:
# - Choose: GitHub.com
# - Choose: HTTPS
# - Authenticate with: Paste an authentication token
# - Paste your GitHub token
```

### D. JIRA API Token (Optional)

1. Go to https://id.atlassian.com/manage-profile/security/api-tokens
2. Click "Create API token"
3. Give it a label: "AudeSec-POC"
4. Copy the token
5. Add to `.env` file with your JIRA URL and email

---

## Step 7: Test the Setup

### Test Docker

```bash
docker run hello-world
```

### Test Trivy

```bash
trivy image alpine:latest
```

### Test GitHub CLI

```bash
gh auth status
```

---

## Step 8: Run the Project

### Option 1: Interactive Mode (Recommended for first run)

```bash
# Make sure virtual environment is activated
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Run the application
python app.py
```

You'll be prompted to enter:
- Git repository URL (e.g., `https://github.com/owner/repo.git`)

### Option 2: Environment Variable Mode

```bash
# Set repository URL
export REPO_URL=https://github.com/your-org/your-repo.git

# Run the application
python app.py
```

### Option 3: With Custom Paths

```bash
export REPO_URL=https://github.com/your-org/your-repo.git
export DEPLOYMENT_YAML_PATH=k8s/deployment.yaml
export PACKAGE_JSON_PATH=backend/package.json
export DOCKERFILE_PATH=docker/Dockerfile
export BRANCH_NAME=security-fixes

python app.py
```

---

## Step 9: What Happens When You Run

The application will:

1. ✅ Clone the specified repository
2. ✅ Find deployment.yaml, package.json, and Dockerfile
3. ✅ Scan Kubernetes configuration for misconfigurations
4. ✅ Build and scan Docker image for CVEs
5. ✅ Create JIRA tickets for critical issues (if configured)
6. ✅ Generate AI-powered fixes using OpenAI
7. ✅ Apply fixes to the repository
8. ✅ Validate the fixed files
9. ✅ Create a new Git branch
10. ✅ Commit the changes
11. ✅ Push to remote and create a Pull Request
12. ✅ Rebuild the container with fixes
13. ✅ Re-scan to verify improvements
14. ✅ Display security improvement metrics

---

## Step 10: Review the Results

After the script completes:

1. **Check the Pull Request**: The script will output a PR URL
2. **Review the Changes**: Look at the diff in the PR
3. **Check Security Metrics**: See before/after comparison
4. **Test the Changes**: Review the fixes before merging

---

## 📁 Project Structure After Running

```
audesec-poc/
├── app.py                      # Main application (run this)
├── config.py                   # Configuration handler
├── .env                        # Your environment variables (DO NOT COMMIT)
├── .env.example               # Template for .env
├── requirements.txt           # Python dependencies
├── README.md                  # Project documentation
├── SETUP_GUIDE.md            # This file
├── WORKFLOW.md               # Detailed workflow documentation
├── venv/                     # Virtual environment (created by you)
├── agents/
│   ├── scanner.py            # K8s scanner
│   ├── image_scanner.py      # Image scanner
│   ├── findings.py           # Findings processor
│   ├── jira_agent.py         # JIRA integration
│   ├── remediation.py        # AI remediation
│   ├── validator.py          # File validator
│   └── git_operations.py     # Git & PR operations
├── reports/                   # Scan reports (auto-generated)
│   ├── k8s_scan.json
│   └── image_scan.json
└── cloned_repo/              # Cloned repository (auto-generated)
    └── (your repository files)
```

---

## 🔧 Troubleshooting

### Issue: "Module not found" errors

```bash
# Make sure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

### Issue: "Docker daemon not running"

```bash
# Start Docker
# macOS: Open Docker Desktop application
# Linux:
sudo systemctl start docker
```

### Issue: "Trivy command not found"

```bash
# Verify installation
which trivy

# If not found, reinstall
# macOS:
brew install trivy

# Linux:
sudo apt install trivy
```

### Issue: "GitHub CLI not authenticated"

```bash
# Re-authenticate
gh auth login
```

### Issue: "OpenAI API error"

- Check your API key is correct in `.env`
- Verify you have credits: https://platform.openai.com/usage
- Check rate limits

### Issue: "Permission denied" when cloning

- For private repos, ensure your GitHub token has `repo` scope
- Or use SSH: `git@github.com:owner/repo.git`

### Issue: "PR creation failed"

```bash
# Check GitHub CLI authentication
gh auth status

# Try creating PR manually
cd cloned_repo
git push origin security-remediation
gh pr create --title "Security Fixes" --body "Automated security remediation"
```

---

## 🎯 Example Run

```bash
$ python app.py

═══ STEP 1: Repository Configuration ═══
Enter Git repository URL: https://github.com/example/vulnerable-app.git
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
  ...

═══ STEP 12: Creating Pull Request ═══
✓ Branch pushed to remote
✓ Pull Request created: https://github.com/example/vulnerable-app/pull/42

═══ STEP 15: Security Improvement Summary ═══
Metric                    Before     After      Improvement    
────────────────────────────────────────────────────────────
CVEs                      47         12         35             
Misconfigurations         5          1          4              

✓ Overall improvement: 85.4%

═══ REMEDIATION COMPLETE ═══
Repository: https://github.com/example/vulnerable-app.git
Branch: security-remediation
Pull Request: https://github.com/example/vulnerable-app/pull/42
```

---

## 📚 Next Steps

1. **Review the PR**: Check the changes in the pull request
2. **Test Locally**: Pull the branch and test the application
3. **Merge**: If everything looks good, merge the PR
4. **Monitor**: Watch for any issues in production

---

## 🆘 Getting Help

- Check `README.md` for detailed documentation
- Review `WORKFLOW.md` for technical details
- Open an issue on GitHub
- Check troubleshooting section above

---

## ⚠️ Important Notes

1. **Never commit `.env` file** - It contains sensitive credentials
2. **Review AI changes** - Always review before merging to production
3. **Test thoroughly** - Test the fixes in a staging environment first
4. **Backup first** - The tool modifies files, ensure you have backups
5. **Rate limits** - Be aware of API rate limits (OpenAI, GitHub)

---

## 🎉 You're Ready!

You should now be able to run the AudeSec-POC project successfully. If you encounter any issues, refer to the troubleshooting section or check the documentation.