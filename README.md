# AudeSec-POC - Automated Security Remediation System

Paste a Git repository URL and AudeSec scans it, opens JIRA tickets for the serious findings, fixes what it can with AI, and raises a pull request against the same repository. The PR is then linked back to each JIRA ticket.

## 📋 How it works

```
repo URL -> clone -> discover files -> scan -> JIRA tickets -> AI remediation
         -> branch / commit / push -> pull request -> PR linked to the JIRA tickets
```

1. **Clone** the repository into a private temporary directory and record its default branch (the PR base).
2. **Discover** files anywhere in the repo: Kubernetes manifests (detected by content: `apiVersion` + `kind`), every `Dockerfile` (`Dockerfile`, `Dockerfile.*`, `*.Dockerfile`) and every `package.json`. `node_modules`, `vendor`, `.git` and symlinks are skipped.
3. **Scan** every manifest (Trivy), build and CVE-scan every Dockerfile (Docker + Trivy), plus SAST (Semgrep) and secrets (Gitleaks) for the whole repo. A repo with no Dockerfile skips the image scan.
4. **JIRA**: one ticket per HIGH/CRITICAL finding, at most 5 per scan (optional).
5. **Remediate** with IBM Bob: each file is fixed and validated on its own, and a bad result for one file is reverted without affecting the others. Dependency (`package.json`) fixes are Node/npm only and are skipped for other ecosystems. Fixed Dockerfiles are rebuilt; if the rebuild fails the change is reverted.
6. **Pull request**: a branch `security-remediation-<id>` is created, **only the files that were really changed** are committed and pushed, and a PR is opened against the default branch. The PR body is generated from the real before/after numbers.
7. **Link**: each JIRA ticket gets a link to the PR and a short summary comment.
8. The clone and every Docker image built during the scan are removed at the end.

The results page shows the PR link, the JIRA keys (as links when `JIRA_URL` is https) and the before/after metrics.

## 🔧 Prerequisites

### Tools (on the machine that runs the app)

| Tool | Used for |
|------|----------|
| Python 3.10+ (3.12 in the image) | the app (`pip install -r requirements.txt`) |
| Git | clone, branch, commit, push |
| Docker | building the repo's Dockerfiles for the CVE scan |
| Trivy | Kubernetes misconfigurations and image CVEs |
| Semgrep | SAST (`pip install -r requirements-semgrep.txt`, ideally in its own virtual environment) |
| Gitleaks | secret scanning (installed separately) |
| Bob CLI (`bob`) | AI remediation |
| Node.js / npm | validating remediated `package.json` dependencies (optional) |

A scanner that is not installed is skipped and reported in the UI; the rest of the scan continues.

The Docker image installs all of them (Git, Docker CLI, Trivy, Gitleaks, Semgrep, Node.js 22 + npm, and Bob Shell `@ibm/bob`) with pinned versions, and the image build fails if any of them is missing. Bob needs Node.js >= 22.15.

### Environment variables

Put these in a `.env` file in the project root (it is loaded at startup), or pass them to Docker with `--env-file`. **Never commit `.env`** - it is listed in `.gitignore`.

| Variable | Required | Purpose |
|----------|----------|---------|
| `BOB_API_KEY` | yes | AI remediation. The scan stops immediately if it is missing. |
| `GITHUB_TOKEN` | for PRs | Token with **write access to the target repository** (contents + pull requests). Used for `git push` and for creating the PR through the GitHub REST API (no GitHub CLI needed). Without it the scan still runs but no PR is raised. |
| `JIRA_URL` | optional | Must be `https://...` for ticket links in the UI. |
| `JIRA_EMAIL`, `JIRA_API_TOKEN` | optional | JIRA credentials (all three `JIRA_*` values are needed to enable JIRA). |
| `JIRA_PROJECT` | optional | Project key for new tickets (default `SEC`). |
| `CSPM_FINDINGS_PATH`, `RUNTIME_FINDINGS_PATH`, `NETWORK_FINDINGS_PATH` | optional | JSON findings exports from cloud / runtime / network tools (examples in `sample_data/`). |
| `AUDESEC_ACCESS_TOKEN` | required unless `HOST` is loopback | Shared token (at least 24 characters) that every `/api/` request must send as `Authorization: Bearer <token>`; the UI asks for it. Generate one with `python -c "import secrets; print(secrets.token_urlsafe(32))"`. |
| `HOST`, `PORT` | optional | Bind address (default `127.0.0.1`) and port (default `8000`). `0.0.0.0` / `::` are refused, and any non-loopback `HOST` requires `AUDESEC_ACCESS_TOKEN`. |
| `ALLOWED_HOSTS` | optional | Comma-separated extra `Host` names accepted (for a reverse proxy). Other `Host` / `Origin` values get HTTP 403 (DNS-rebinding defence). |
| `MAX_CONCURRENT_SCANS` | optional | Scans running at once (default `2`); more get HTTP 429. |
| `SCAN_RETENTION_SECONDS` | optional | How long finished scan results stay in memory (default 24 h). |
| `WEB_THREADS` | optional | Server threads (default `8`). |
| `BOB_TIMEOUT_SECONDS`, `DOCKER_BUILD_TIMEOUT_SECONDS` | optional | Time limits for one Bob call (default 600) and one `docker build` (default 1200). |
| `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL` | optional | Identity on the remediation commit (default `audesec-bot`). |
| `PRUNE_BUILD_CACHE` | optional | `true` (default): after each scan, also prune unused Docker build cache. Set `false` on a shared Docker host if you want to keep other projects' cache. |
| `LOG_LEVEL` | optional | Python log level (default `INFO`). |

The token is passed to git only through the process environment (scoped to `github.com`) and to the GitHub API in an `Authorization` header over HTTPS (redirects are not followed). It is never written into a remote URL, `.git/config`, command-line arguments, logs or the UI.

### Scanners

| Scanner | Tool | Source |
|---------|------|--------|
| Kubernetes misconfigurations | Trivy | every manifest found in the repo |
| Container image CVEs | Trivy | one image per Dockerfile found |
| SAST (code vulnerabilities) | Semgrep | repo source code |
| Secrets | Gitleaks | repo source code (values are redacted) |
| Cloud posture (CSPM) | Trivy, plus an optional JSON export | the repo's infrastructure-as-code (Terraform, CloudFormation, Helm, Azure ARM, ...), plus the file named by `CSPM_FINDINGS_PATH` (e.g. Prowler) |
| Runtime security | JSON export (Falco, ...) | the file named by `RUNTIME_FINDINGS_PATH` |
| Network exposure | JSON export (kube-hunter, ...) | the file named by `NETWORK_FINDINGS_PATH` |

SAST and secret findings are fixed in the cloned source. Cloud posture findings are reported with AI recommendations in the results page (`advisory` in `/api/scan/<id>`) and are not changed automatically.

Runtime and network findings describe a running cluster, not a repository, so they come from exports of your own tools (formats in `sample_data/`). When a `*_FINDINGS_PATH` variable is unset or points to a missing file, that step is shown as skipped. These findings, like cloud posture ones, get AI recommendations in the results page and are not applied to the repo automatically.

## 🚀 How to Run

### Local

```bash
python3.12 -m venv venv && source venv/bin/activate     # Python 3.10+ is required
pip install --require-hashes -r requirements.txt
python3.12 -m venv venv-semgrep && venv-semgrep/bin/pip install --require-hashes -r requirements-semgrep.txt
export PATH="$PWD/venv-semgrep/bin:$PATH"                # so the app finds `semgrep`

# create .env with the variables above, then:
python -m remediator.web.app
# open http://127.0.0.1:8000
```

The startup log lists which settings are set (names only, never values).

**Command line:** the same workflow without the browser: `python -m remediator.cli https://github.com/owner/repo.git` (prints the PR URL and JIRA keys; the exit code is non-zero on failure).

**Dependencies:** `requirements.in` / `requirements-semgrep.in` list the direct packages; `requirements.txt` / `requirements-semgrep.txt` are the hash-locked results. Regenerate them (Python 3.12) with `pip-compile --generate-hashes --allow-unsafe -o requirements.txt requirements.in` (and the same for the semgrep pair), then audit with `pip-audit -r requirements.txt`. Semgrep pins `mcp`, `opentelemetry-api` and `wcmatch` to versions that have published advisories; they run only inside the separate semgrep environment, never in the web app.

### Docker

```bash
docker build -t audesec-platform .
docker run -d --name audesec \
  -p 127.0.0.1:8000:8000 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --group-add "$(stat -c %g /var/run/docker.sock)" \
  --env-file .env \
  audesec-platform
# open http://127.0.0.1:8000
```

`.env` is excluded from the build context (`.dockerignore`), so secrets never end up in an image layer; they come only from `--env-file`. On macOS with Docker Desktop or Colima, replace the `--group-add` value with the group id of the socket inside the VM (`docker run --rm -v /var/run/docker.sock:/s alpine stat -c %g /s`).

The image is based on Red Hat UBI 9 (`ubi9/python-312-minimal`), runs as the non-root user `1001`, and the build verifies every tool (`git`, `docker`, `trivy`, `gitleaks`, `semgrep`, `node`, `npm`, `bob`). Tool downloads are pinned and checksum-verified, and Python packages are installed with `--require-hashes`. Inside the container the app binds to the container's own address (never `0.0.0.0`) unless you set `HOST`; because that is not a loopback address, **`AUDESEC_ACCESS_TOKEN` must be set** (put it in `.env`). Keep the port published on `127.0.0.1` as above. `GET /healthz` is the health check. The container needs the Docker socket to build the target repo's Dockerfiles, which gives it control of the host's Docker, so only run it on a machine you trust.

### Using the web UI

1. Enter a repository URL: `https://host/owner/repo(.git)`, `ssh://...` or `git@host:owner/repo.git`. Anything else (leading `-`, `file:`, `ext::`, `http://`, whitespace) is rejected with HTTP 400 before git runs.
2. Click **Start Scan** and follow the steps in real time.
3. Review the result: PR link, JIRA tickets, changed files, before/after metrics. **Always review the PR before merging.**

## ⚠️ Behaviour when something is missing or fails

The scan itself always finishes. The PR step reports why no PR was raised (shown in the UI and as `pr_status` in `/api/scan/<id>`).

| Situation | Result |
|-----------|--------|
| Invalid repository URL | HTTP 400, nothing is cloned |
| `BOB_API_KEY` missing | scan stops at the start with an error |
| No `GITHUB_TOKEN` | scan and fixes run, **no PR** (`no_token`) |
| Remediation changed nothing | no branch, no PR (`no_changes`) |
| Push denied / token has no write access | **no PR** (`push_failed`); there is no fork fallback |
| PR creation fails after the push (for example the token lacks pull-request permission, or a PR for the branch already exists) | the branch stays pushed, error reported (`failed`) |
| Host is not GitHub (GitLab, Bitbucket, look-alike hosts, ...) | scan and fixes run, **PR not supported** (`unsupported_host`) |
| JIRA not configured | no tickets, the PR is still raised |
| `JIRA_URL` is not https | tickets are created and linked, keys shown as plain text in the UI |
| Linking one ticket fails | the other tickets are still linked, the scan is not affected |
| The AI's fix for a file is invalid | that file is reverted, the others are kept |
| A Dockerfile does not build | it is not scanned, or its change is reverted after a failed rebuild |

**UBI base images:** Dockerfiles that the AI rewrites use Red Hat UBI images from `registry.access.redhat.com`, which needs **no login** (`registry.redhat.io/ubi*` references are rewritten to it). A Dockerfile in the target repo that itself uses `registry.redhat.io` needs `docker login registry.redhat.io` on the host.

## 🧪 Tests

The unit tests are offline: no network, Docker, Trivy, Bob, JIRA or real credentials. They never read `.env` or touch the repository's own git state; they use temp dirs, local bare git repositories and stubs. Only the standard library (`unittest`) is used, so nothing needs installing beyond `requirements.txt`.

```bash
python -m unittest discover -s tests -t .
```

They cover file discovery, URL / branch-name validation, GitHub URL parsing, selective commit and token-free push against a local origin, the GitHub API request for the PR, the PR body, the JIRA helpers, the JIRA base URL check, `POST /api/scan` validation, and whole `run_security_scan` runs (PR + linked tickets, no token, no changes, push denied, non-GitHub URL, JIRA not configured, no manifests/Dockerfile, nested and multiple assets).

## ✅ Manual live-verification checklist

These need real accounts and tools, so run them yourself. Use a throw-away GitHub repository you can write to, a test JIRA project and a scoped token.

1. **Setup**: `docker info`, `trivy --version`, `gitleaks version`, `bob --version` work; `.env` has `BOB_API_KEY`, `GITHUB_TOKEN` and `JIRA_*`; the startup log shows them as `set`.
2. **Sample Node repo** (manifest + Dockerfile + `package.json`): a PR is created against the default branch and changes only remediated files; its body lists files, before/after numbers and JIRA keys; each ticket (max 5) has a remote link and a comment with the PR URL; ticket and PR links in the UI open in a new tab.
3. **Python-only repo** (no Dockerfile, manifest or `package.json`): the scan completes without errors, the image scan is skipped ("No Dockerfile found"), and a PR is raised only if SAST/secret fixes changed something.
4. **Nested / multiple assets** (manifests in subfolders, several Dockerfiles such as `svc/a/Dockerfile` and `svc/b/Dockerfile.prod`, several `package.json`): every one is discovered and scanned, and the commit has the correct relative paths.
5. **Failure paths**
   - empty `GITHUB_TOKEN`: `no_token`, no PR, tickets still listed.
   - read-only token, or a repo you cannot write to: `push_failed`, no PR.
   - non-GitHub URL: `unsupported_host`.
   - `JIRA_*` removed: no tickets, PR still created, "No JIRA tickets were created."
   - `JIRA_URL=http://...`: keys are plain text.
   - invalid URL such as `--upload-pack=x`: alert (HTTP 400).
   - repo with nothing to fix: `no_changes`.
6. **Cleanup**: after each scan there is no `security-remediation-clone-*` directory in the working directory and `docker images` shows no `*-scan-*` images. Delete the test branches/PRs on GitHub.

## 📁 Project Structure

```
audesec-poc/
├── remediator/                 # Python package (all application code)
│   ├── cli.py                  # Command-line entry point (python -m remediator.cli)
│   ├── config.py               # Configuration and file discovery
│   ├── findings.py             # Findings normalization
│   ├── logger.py               # Activity logging
│   ├── scanners/               # Trivy (K8s, images, IaC), Semgrep, Gitleaks, JSON feeds (cloud, runtime, network)
│   ├── remediation/            # AI fixing (Bob client; K8s, package.json, Dockerfile, source)
│   ├── validation/             # Checks on fixed files
│   ├── integrations/
│   │   ├── git_operations.py   #   clone, branch, commit, push, PR (GitHub REST API), PR body
│   │   └── jira_agent.py       #   JIRA tickets and PR links
│   └── web/
│       ├── app.py              #   Flask backend, served by waitress (python -m remediator.web.app)
│       ├── security.py         #   access token, Host/Origin check, security headers
│       └── store.py            #   thread-safe scan state with retention and a concurrency cap
├── remediator-ui/              # Frontend (served by the Flask backend; no inline scripts)
├── sample_data/                # Example CSPM / runtime / network JSON exports
├── tests/                      # Offline unit tests
├── requirements.in             # Direct dependencies of the app
├── requirements.txt            # Hash-locked app dependencies
├── requirements-semgrep.in     # Semgrep (installed in its own environment)
├── requirements-semgrep.txt    # Hash-locked Semgrep dependencies
├── Dockerfile
├── .env                        # Your settings and secrets (create it; never commit)
└── security-remediation-clone-*/   # Per-scan clones (generated, removed after each scan)
```

## 🔒 Security Best Practices

- Never commit `.env`; rotate tokens regularly.
- Give `GITHUB_TOKEN` the minimum scope: write access to the repositories you scan, nothing else.
- Keep the UI bound to `127.0.0.1`. Anything reachable from other machines must set `AUDESEC_ACCESS_TOKEN` (enforced at startup) and sit behind TLS (a reverse proxy; add its name to `ALLOWED_HOSTS`).
- The API rejects unknown `Host` / `Origin` headers, sends a strict Content-Security-Policy, and returns generic error messages (details only in the server log).
- Always review AI-generated PRs and test them before merging.

## 🐳 Docker Management Commands

```bash
docker logs -f audesec        # view logs
docker stop audesec           # stop
docker start audesec          # start again
docker rm -f audesec          # remove container
docker rmi audesec-platform   # remove image
docker exec -it audesec bash  # shell inside the container
```

## 🐛 Troubleshooting

- **Port in use / UI not reachable**: `lsof -i :8000`, or set `PORT`, or change the `-p` mapping.
- **"Git clone failed"**: check the URL and your access. Private repos need credentials git can use non-interactively (prompts are disabled).
- **No PR was created**: read the Pull Request step message. `no_token`, `push_failed` (token lacks write access) and `unsupported_host` are described above. For `failed`, read the server log: it shows GitHub's error (for example a token without pull-request permission).
- **"Docker build failed"**: in Docker, make sure `/var/run/docker.sock` is mounted. For `registry.redhat.io` images run `docker login registry.redhat.io`.
- **Trivy errors**: update its database with `trivy image --download-db-only` and check network access.
- **Detailed logs**: set `LOG_LEVEL=DEBUG`. Secrets and URL credentials are never logged.

## 🤝 Contributing

1. Fork the repository and create a feature branch.
2. Make your changes and run the tests (`python -m unittest discover -s tests -t .`).
3. Submit a pull request.

## 📄 License

This project is for proof-of-concept purposes.

## 🔗 Related Tools

- [Trivy](https://github.com/aquasecurity/trivy) - vulnerability scanner
- [Semgrep](https://semgrep.dev/) - SAST
- [Gitleaks](https://github.com/gitleaks/gitleaks) - secret scanner
- [GitHub REST API](https://docs.github.com/en/rest/pulls/pulls#create-a-pull-request) - pull request creation

---

**Note**: This is a proof-of-concept tool. Always review AI-generated changes before merging to production.
