# AudeSec-POC Workflow Documentation

## Complete Code Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    USER INPUT / CONFIGURATION                    │
│  • Git Repository URL                                            │
│  • File paths (deployment.yaml, package.json, Dockerfile)       │
│  • Branch name for remediation                                  │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    STEP 1: CLONE REPOSITORY                      │
│  Module: agents/git_operations.py                               │
│  Function: clone_repository()                                   │
│  • Clones Git repository to local directory                     │
│  • Removes existing clone if present                            │
│  Output: Local repository path                                  │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    STEP 2: FILE DISCOVERY                        │
│  Module: config.py                                              │
│  Function: find_files_in_repo()                                 │
│  • Searches for deployment.yaml                                 │
│  • Searches for package.json                                    │
│  • Searches for Dockerfile                                      │
│  Output: Dictionary of file paths                               │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              STEP 3: KUBERNETES SECURITY SCAN                    │
│  Module: agents/scanner.py                                      │
│  Functions: scan_k8s_config() → summarize_findings()            │
│  • Runs Trivy config scan on deployment.yaml                    │
│  • Extracts misconfigurations                                   │
│  • Categorizes by severity (CRITICAL, HIGH, MEDIUM, LOW)        │
│  Output: List of K8s findings                                   │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              STEP 4: CONTAINER IMAGE CVE SCAN                    │
│  Module: agents/image_scanner.py                                │
│  Functions: scan_image() → summarize_cves()                     │
│  • Builds Docker image from Dockerfile                          │
│  • Runs Trivy image scan                                        │
│  • Extracts CVE vulnerabilities                                 │
│  • Identifies vulnerable packages and versions                  │
│  Output: List of CVE findings                                   │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                STEP 5: COMBINE & NORMALIZE FINDINGS              │
│  Module: agents/findings.py                                     │
│  Function: combine_findings()                                   │
│  • Normalizes K8s findings (type: MISCONFIG)                    │
│  • Normalizes CVE findings (type: CVE)                          │
│  • Merges into unified format                                   │
│  • Filters HIGH/CRITICAL severity issues                        │
│  Output: Combined findings list                                 │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                STEP 6: JIRA TICKET CREATION                      │
│  Module: agents/jira_agent.py                                   │
│  Function: create_jira_ticket()                                 │
│  • Creates tickets for HIGH/CRITICAL issues (max 5)             │
│  • Includes vulnerability details                               │
│  • Links to remediation (optional)                              │
│  Output: List of JIRA ticket IDs                                │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              STEP 7: AI-POWERED REMEDIATION                      │
│  Module: agents/remediation.py                                  │
│  Function: generate_remediation()                               │
│  • Sends findings + files to OpenAI GPT-4.1-mini                │
│  • AI generates fixed deployment.yaml                           │
│  • AI generates fixed package.json                              │
│  • Preserves application functionality                          │
│  Output: Remediated file contents                               │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                STEP 8: APPLY REMEDIATION                         │
│  Module: app.py (main workflow)                                 │
│  • Parses AI response                                           │
│  • Writes fixed deployment.yaml to repository                   │
│  • Writes fixed package.json to repository                      │
│  Output: Updated files in repository                            │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    STEP 9: VALIDATION                            │
│  Module: agents/validator.py                                    │
│  Functions: validate_yaml(), validate_package_json()            │
│  • Validates YAML syntax                                        │
│  • Validates JSON syntax                                        │
│  • Ensures files are parseable                                  │
│  Output: Validation status (pass/fail)                          │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              STEP 10: GIT BRANCH & COMMIT                        │
│  Module: agents/git_operations.py                               │
│  Functions: create_branch(), commit_changes()                   │
│  • Creates new branch (e.g., security-remediation)              │
│  • Stages all changes                                           │
│  • Commits with detailed message                                │
│  Output: New branch with committed changes                      │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              STEP 11: PUSH & CREATE PULL REQUEST                 │
│  Module: agents/git_operations.py                               │
│  Functions: push_branch(), create_pull_request()                │
│  • Pushes branch to remote repository                           │
│  • Creates PR via GitHub CLI                                    │
│  • Includes security metrics in PR description                  │
│  • Lists all fixed vulnerabilities                              │
│  Output: Pull Request URL                                       │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              STEP 12: REBUILD CONTAINER IMAGE                    │
│  Module: app.py (main workflow)                                 │
│  • Builds new Docker image with fixed files                     │
│  • Tags as remediated-{repo-name}                               │
│  Output: New container image                                    │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              STEP 13: RE-SCAN FIXED ASSETS                       │
│  Modules: agents/scanner.py, agents/image_scanner.py            │
│  • Re-scans fixed deployment.yaml                               │
│  • Re-scans remediated container image                          │
│  • Compares before/after metrics                                │
│  Output: Updated findings lists                                 │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              STEP 14: SECURITY IMPROVEMENT REPORT                │
│  Module: app.py (main workflow)                                 │
│  • Calculates CVE reduction                                     │
│  • Calculates misconfiguration reduction                        │
│  • Computes improvement percentage                              │
│  Output: Security metrics report                                │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                      COMPLETION                                  │
│  • Pull Request created with fixes                              │
│  • Security improvements documented                             │
│  • Ready for review and merge                                   │
└─────────────────────────────────────────────────────────────────┘
```

## Module Responsibilities

### 1. **config.py**
- **Purpose**: Configuration management and file discovery
- **Key Functions**:
  - `get_repo_config_from_input()`: Gets repository URL from user or env
  - `find_files_in_repo()`: Locates required files in repository
- **Input**: User input or environment variables
- **Output**: RepoConfig object and file paths dictionary

### 2. **agents/git_operations.py**
- **Purpose**: Git operations and PR management
- **Key Functions**:
  - `clone_repository()`: Clones Git repository
  - `create_branch()`: Creates new branch
  - `commit_changes()`: Commits changes
  - `push_branch()`: Pushes to remote
  - `create_pull_request()`: Creates PR via GitHub CLI
  - `generate_pr_body()`: Generates PR description
- **Dependencies**: Git, GitHub CLI
- **Output**: Repository path, branch name, PR URL

### 3. **agents/scanner.py**
- **Purpose**: Kubernetes configuration security scanning
- **Key Functions**:
  - `scan_k8s_config()`: Runs Trivy config scan
  - `summarize_findings()`: Extracts and formats findings
- **Dependencies**: Trivy
- **Input**: Path to deployment.yaml
- **Output**: List of misconfigurations with severity

### 4. **agents/image_scanner.py**
- **Purpose**: Container image vulnerability scanning
- **Key Functions**:
  - `scan_image()`: Runs Trivy image scan
  - `summarize_cves()`: Extracts CVE information
- **Dependencies**: Trivy, Docker
- **Input**: Docker image name
- **Output**: List of CVEs with package details

### 5. **agents/findings.py**
- **Purpose**: Normalize and combine security findings
- **Key Functions**:
  - `normalize_k8s_findings()`: Standardizes K8s findings
  - `normalize_cves()`: Standardizes CVE findings
  - `combine_findings()`: Merges all findings
- **Input**: K8s findings and CVE findings
- **Output**: Unified findings list

### 6. **agents/jira_agent.py**
- **Purpose**: JIRA ticket creation for tracking
- **Key Functions**:
  - `create_jira_ticket()`: Creates JIRA issue
- **Dependencies**: JIRA API, python-jira library
- **Input**: Finding object
- **Output**: JIRA ticket ID

### 7. **agents/remediation.py**
- **Purpose**: AI-powered security remediation
- **Key Functions**:
  - `generate_remediation()`: Uses OpenAI to fix issues
- **Dependencies**: OpenAI API
- **Input**: Findings, deployment.yaml, package.json
- **Output**: Fixed file contents

### 8. **agents/validator.py**
- **Purpose**: Validate generated files
- **Key Functions**:
  - `validate_yaml()`: Validates YAML syntax
  - `validate_package_json()`: Validates JSON syntax
- **Input**: File paths
- **Output**: Boolean validation status

### 9. **app.py**
- **Purpose**: Main orchestration workflow
- **Responsibilities**:
  - Coordinates all modules
  - Manages workflow sequence
  - Handles errors and user feedback
  - Displays progress and results

## Data Flow

### Input Data
```python
{
    "repo_url": "https://github.com/owner/repo.git",
    "deployment_yaml_path": "deployment.yaml",
    "package_json_path": "package.json",
    "dockerfile_path": "Dockerfile",
    "branch_name": "security-remediation"
}
```

### Scan Results
```python
{
    "k8s_findings": [
        {
            "id": "KSV001",
            "title": "Container should not run as root",
            "severity": "HIGH",
            "message": "..."
        }
    ],
    "cves": [
        {
            "cve": "CVE-2023-1234",
            "package": "express",
            "installed": "4.17.1",
            "fixed": "4.18.2",
            "severity": "CRITICAL"
        }
    ]
}
```

### Combined Findings
```python
[
    {
        "type": "MISCONFIG",
        "id": "KSV001",
        "severity": "HIGH",
        "title": "Container should not run as root",
        "message": "..."
    },
    {
        "type": "CVE",
        "id": "CVE-2023-1234",
        "severity": "CRITICAL",
        "package": "express",
        "installed_version": "4.17.1",
        "fixed_version": "4.18.2"
    }
]
```

### Remediation Output
```
===FIXED_DEPLOYMENT===
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      containers:
      - name: app
        image: app:latest
        resources:
          limits:
            cpu: "1"
            memory: "512Mi"

===FIXED_PACKAGE_JSON===
{
  "name": "app",
  "dependencies": {
    "express": "^4.18.2"
  }
}
```

## Error Handling

### Common Errors and Recovery

1. **Git Clone Failure**
   - Check repository URL
   - Verify access permissions
   - Ensure SSH keys or tokens are configured

2. **File Not Found**
   - System searches common locations
   - Warns user if files missing
   - Continues with available files

3. **Scan Failures**
   - Logs error details
   - Continues with other scans
   - Reports partial results

4. **AI Remediation Errors**
   - Validates response format
   - Retries on format errors
   - Falls back to manual review

5. **PR Creation Failures**
   - Provides manual push instructions
   - Saves branch locally
   - User can create PR manually

## Performance Considerations

- **Parallel Scanning**: K8s and image scans could run in parallel
- **Caching**: Trivy caches vulnerability database
- **Incremental Updates**: Only scans changed files
- **Rate Limiting**: Respects API rate limits (OpenAI, GitHub, JIRA)

## Security Considerations

- **Secrets**: Never commits .env file
- **Tokens**: Uses environment variables
- **Validation**: All AI outputs are validated
- **Review**: PRs require human review before merge
- **Isolation**: Cloned repos in separate directory

## Future Enhancements

1. **Multi-language Support**: Python, Java, Go, etc.
2. **Custom Rules**: User-defined security policies
3. **Rollback**: Automatic rollback on test failures
4. **Notifications**: Slack/Email notifications
5. **Dashboard**: Web UI for monitoring
6. **Batch Processing**: Multiple repositories
7. **Scheduled Scans**: Periodic security checks
8. **Integration Tests**: Automated testing of fixes