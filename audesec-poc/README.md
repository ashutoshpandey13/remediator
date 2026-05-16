# AudeSec-POC - Automated Security Remediation System

An intelligent security remediation system that automatically scans, detects, fixes, and validates security vulnerabilities in Kubernetes deployments and container images.

## 🚀 New Features

### 🌐 Web UI (NEW!)
- **User-friendly web interface** - No command line needed!
- **Real-time progress updates** via WebSocket
- **Visual metrics dashboard** showing security improvements
- **Step-by-step workflow visualization**
- **Responsive design** - Works on desktop and mobile

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

## 🚀 How to Run

### Using Docker (Recommended)

The simplest way to run AudeSec with all dependencies pre-configured:

```bash
# 1. Clone the repository
git clone <your-repo-url>
cd audesec-poc

# 2. Build the Docker image
docker build -t audesec-platform .

# 3. Run the container
docker run -d \
  --name audesec \
  -p 8000:8000 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/fixed:/app/fixed \
  audesec-platform

# 4. Access the web UI
# Open browser to: http://localhost:8000

# 5. View logs (optional)
docker logs -f audesec

# 6. Stop the container (when done)
docker stop audesec
docker rm audesec
```

**That's it!** The application runs with all API keys and dependencies pre-configured in the Docker image.

### Local Development (Without Docker)

For development or if you prefer running without Docker:

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Create .env file
cp .env.example .env

# 3. Edit .env and add your API keys
nano .env  # or use your preferred editor

# 4. Run the web application
python web_app.py

# 5. Access at: http://localhost:5000
```

## 🎯 How to Use

### Web Interface (Recommended)

1. **Access the application** at `http://localhost:8000`
2. **Enter repository URL** in the web form
3. **Click "Start Scan"** to begin the security remediation workflow
4. **Monitor progress** in real-time through the web interface
5. **Review results** including:
   - Security vulnerabilities found
   - Automated fixes applied
   - Pull request created with remediation
   - Before/after security metrics

### Command Line Interface

For automation or scripting:

```bash
# Using Docker
docker exec -it audesec python app.py

# Or locally (after activating venv if used)
python app.py
```

The CLI will prompt you for the repository URL and guide you through the process.

## ⚙️ Configuration (Optional)

The Docker image includes pre-configured environment variables. You only need to customize them if you want to use your own API keys.

### Override Environment Variables (Docker)

Pass custom environment variables when running the container:

```bash
docker run -d \
  --name audesec \
  -p 8000:8000 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/fixed:/app/fixed \
  -e OPENAI_API_KEY=your_custom_key \
  -e GITHUB_TOKEN=your_custom_token \
  -e JIRA_URL=https://your-domain.atlassian.net \
  -e JIRA_EMAIL=your-email@example.com \
  -e JIRA_API_TOKEN=your_jira_token \
  -e JIRA_PROJECT=YOUR_PROJECT \
  audesec-platform
```

### Local Development Configuration

Create a `.env` file with your credentials:

```bash
# Required
OPENAI_API_KEY=sk-your-openai-api-key
GITHUB_TOKEN=ghp_your-github-token

# Optional (for JIRA integration)
JIRA_URL=https://your-domain.atlassian.net
JIRA_EMAIL=your-email@example.com
JIRA_API_TOKEN=your-jira-token
JIRA_PROJECT=PROJ
```

## 🐳 Docker Management Commands

```bash
# View logs
docker logs -f audesec

# Stop container
docker stop audesec

# Start stopped container
docker start audesec

# Restart container
docker restart audesec

# Remove container
docker rm audesec

# Remove container and image
docker rm -f audesec
docker rmi audesec-platform

# Execute commands inside container
docker exec -it audesec bash
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

### Container Won't Start

```bash
# Check logs
docker logs audesec

# Common issues:
# 1. Port 8000 already in use
sudo lsof -i :8000
# Kill the process or use a different port: -p 9000:8000

# 2. Docker daemon not running
docker info
# Start Docker Desktop or Docker daemon

# 3. Permission denied on Docker socket
sudo chmod 666 /var/run/docker.sock
```

### Can't Access Web UI

```bash
# Verify container is running
docker ps | grep audesec

# Check container health
docker inspect --format='{{.State.Health.Status}}' audesec

# Test connection
curl http://localhost:8000

# If using different port, adjust URL accordingly
```

### "Git clone failed" in Application

- Check repository URL is correct
- Verify you have access to the repository
- For private repos, ensure GitHub token has proper permissions
- Check container logs: `docker logs audesec`

### "Docker build failed" Inside Container

```bash
# Verify Docker socket is mounted
docker exec audesec ls -la /var/run/docker.sock

# Test Docker access from inside container
docker exec audesec docker ps

# If permission denied, check Docker socket permissions on host
ls -la /var/run/docker.sock
```

### "Trivy scan failed"

```bash
# Update Trivy database inside container
docker exec audesec trivy image --download-db-only

# Check Trivy version
docker exec audesec trivy --version

# Verify internet connectivity from container
docker exec audesec ping -c 3 google.com
```

### Out of Memory or Slow Performance

```bash
# Check container resource usage
docker stats audesec

# Restart container with more resources
docker stop audesec
docker rm audesec
docker run -d \
  --name audesec \
  -p 8000:8000 \
  --memory="4g" \
  --cpus="2.0" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  audesec-platform
```

### View Detailed Logs

```bash
# Real-time logs
docker logs -f audesec

# Last 100 lines
docker logs --tail 100 audesec

# Logs with timestamps
docker logs -t audesec
```

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