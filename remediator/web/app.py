from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import threading
import os
import subprocess
import logging
import re
from datetime import datetime
from urllib.parse import urlparse
import json

from remediator.config import get_repository_config, discover_repo_files, is_k8s_manifest
from remediator.integrations.git_operations import (
    clone_repository,
    cleanup_cloned_repo,
    cleanup_stale_clones,
    get_default_branch,
    validate_repo_url,
    validate_branch_name,
    parse_github_repo,
    UnsupportedRepositoryHost,
    scrub_secrets,
    create_branch,
    commit_changes,
    push_branch,
    create_pull_request,
    generate_remediation_pr_body
)
from remediator.scanners.scanner import scan_k8s_config, summarize_findings
from remediator.scanners.image_scanner import scan_image, summarize_cves
from remediator.scanners.sast_scanner import scan_code, summarize_sast
from remediator.scanners.secret_scanner import scan_secrets, summarize_secrets
from remediator.scanners.cspm_scanner import scan_cspm, summarize_cspm
from remediator.findings import combine_findings
from remediator.integrations.jira_agent import create_jira_ticket, link_pr_to_ticket, is_jira_configured
from remediator.remediation.bob_client import ensure_bob_configured
from remediator.remediation.remediation import generate_remediation
from remediator.remediation.source_remediation import apply_source_fixes
from remediator.remediation.advisory import generate_advisory
from remediator.validation.validator import validate_yaml, validate_package_json
from remediator.validation.dependency_validator import (
    npm_available,
    validate_npm_package,
    find_missing_node_dependencies
)
from remediator.remediation.dockerfile_remediation import generate_dockerfile_remediation
from remediator.logger import log_activity

logging.basicConfig(
    level=os.getenv('LOG_LEVEL', 'INFO').upper(),
    format='%(asctime)s %(levelname)s %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)

# Credentials embedded in URLs (https://user:token@host/...) must never reach the logs
_URL_CREDENTIALS = re.compile(r'(?<=//)[^/@\s]+@')

# The frontend lives in <project root>/remediator-ui
UI_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "remediator-ui")
)

app = Flask(
    __name__,
    template_folder=os.path.join(UI_DIR, "templates"),
    static_folder=os.path.join(UI_DIR, "static"),
)
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app, cors_allowed_origins="*")

# Store scan results
scan_results = {}

# Workflow steps: (id, icon, title, default message).
# The template renders this list, so the UI always matches the workflow below.
STEP_CLEANUP = 0
STEP_CONFIG = 1
STEP_CLONE = 2
STEP_DISCOVER = 3
STEP_K8S = 4
STEP_IMAGE = 5
STEP_SAST = 6
STEP_SECRETS = 7
STEP_CSPM = 8
STEP_RUNTIME = 9
STEP_NETWORK = 10
STEP_COMBINE = 11
STEP_JIRA = 12
STEP_REMEDIATE = 13
STEP_APPLY = 14
STEP_SOURCE_FIX = 15
STEP_ADVISORY = 16
STEP_VALIDATE = 17
STEP_DOCKERFILE = 18
STEP_REBUILD = 19
STEP_RESCAN = 20
STEP_METRICS = 21
STEP_PR = 22
STEP_JIRA_LINK = 23

STEPS = [
    (STEP_CLEANUP, "🧹", "Cleanup", "Preparing environment..."),
    (STEP_CONFIG, "⚙️", "Configuration", "Loading repository configuration..."),
    (STEP_CLONE, "📥", "Clone Repository", "Cloning repository..."),
    (STEP_DISCOVER, "🔍", "File Discovery", "Discovering files..."),
    (STEP_K8S, "☸️", "Kubernetes Scan", "Scanning Kubernetes configurations..."),
    (STEP_IMAGE, "🐳", "Container Scan", "Building and scanning container image..."),
    (STEP_SAST, "🧬", "SAST Scan", "Scanning source code for vulnerabilities..."),
    (STEP_SECRETS, "🔑", "Secret Scan", "Scanning for hardcoded secrets..."),
    (STEP_CSPM, "☁️", "Cloud Posture (IaC)", "Scanning infrastructure-as-code for cloud misconfigurations..."),
    (STEP_RUNTIME, "🏃", "Runtime Security", "Runtime security is not part of a repository scan..."),
    (STEP_NETWORK, "🌐", "Network Exposure", "Network exposure is not part of a repository scan..."),
    (STEP_COMBINE, "📊", "Combine Findings", "Analyzing security findings..."),
    (STEP_JIRA, "🎫", "JIRA Tickets", "Creating tracking tickets..."),
    (STEP_REMEDIATE, "🤖", "AI Remediation", "Generating fixes with AI..."),
    (STEP_APPLY, "✏️", "Apply Fixes", "Applying security fixes..."),
    (STEP_SOURCE_FIX, "🛠️", "Source Code Fixes", "Fixing code vulnerabilities and secrets..."),
    (STEP_ADVISORY, "📝", "Posture Advisory", "Recommending cloud posture fixes..."),
    (STEP_VALIDATE, "✅", "Validation", "Validating fixed files..."),
    (STEP_DOCKERFILE, "🔧", "Dockerfile Update", "Updating Dockerfile..."),
    (STEP_REBUILD, "🔨", "Rebuild Container", "Rebuilding container image..."),
    (STEP_RESCAN, "🔄", "Re-scan", "Re-scanning fixed assets..."),
    (STEP_METRICS, "📈", "Metrics", "Calculating improvement metrics..."),
    (STEP_PR, "🔀", "Pull Request", "Raising pull request..."),
    (STEP_JIRA_LINK, "🔗", "JIRA Links", "Linking the pull request to JIRA tickets..."),
]

JIRA_SEVERITIES = ("HIGH", "CRITICAL")

# Findings sent to the AI for one package.json
MAX_PACKAGE_FINDINGS = 20

DEPENDENCY_SECTIONS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies"
)


def emit_progress(scan_id, step, status, message, data=None):
    """Emit progress update to the client."""
    progress = {
        'scan_id': scan_id,
        'step': step,
        'status': status,  # 'running', 'success', 'error', 'info'
        'message': message,
        'timestamp': datetime.now().isoformat(),
        'data': data
    }
    log_level = logging.ERROR if status == 'error' else logging.INFO
    logger.log(log_level, '[%s] step=%s status=%s %s',
               scan_id, step, status, _URL_CREDENTIALS.sub('', message))
    socketio.emit('progress_update', progress, room=scan_id)
    
    # Store in results
    if scan_id not in scan_results:
        scan_results[scan_id] = {'steps': [], 'status': 'running'}
    scan_results[scan_id]['steps'].append(progress)


def run_optional_scan(scan_id, step, label, scan_fn):
    """
    Run one scanner. A scanner that is not installed or that fails must not
    abort the whole workflow, so the failure is reported as an info step and
    the details are logged server-side only.

    Returns:
        (findings, ran) - ran is False when the scanner could not run.
    """
    emit_progress(scan_id, step, 'running', f'Running {label}...')

    try:
        findings = scan_fn()
    except FileNotFoundError:
        emit_progress(scan_id, step, 'info', f'{label} skipped: scanner is not installed')
        return [], False
    except Exception:
        logger.exception("%s failed", label)
        emit_progress(scan_id, step, 'info', f'{label} skipped: scan failed (see server log)')
        return [], False

    emit_progress(scan_id, step, 'success', f'{label} found {len(findings)} issues', {
        'count': len(findings),
        'detail': f'({len(findings)} issues)'
    })
    log_activity(f'{label} completed')
    return findings, True


def metric(before, after):
    """Before/after/fixed/improvement numbers for one category."""
    fixed = before - after
    improvement = (fixed / before * 100) if before > 0 else 0
    return {
        'before': before,
        'after': after,
        'fixed': fixed,
        'improvement': round(improvement, 1)
    }


def read_text(path):
    with open(path, 'r') as f:
        return f.read()


def write_text(path, text):
    with open(path, 'w') as f:
        f.write(text)


def extract_fixed_content(reply, marker):
    """The fixed file from a single-file generate_remediation reply ('' if there is none)."""
    if marker in reply:
        reply = reply.split(marker, 1)[1]
    return reply.strip()


def repo_relative(clone_dir, path):
    """A scanner-reported file path as a path relative to the clone ('' if unknown)."""
    if not path:
        return ''
    if os.path.isabs(path) or path.startswith(clone_dir):
        return os.path.relpath(os.path.abspath(path), clone_dir)
    return os.path.normpath(path)


def package_json_findings(clone_dir, all_findings, package_json_rel, package_json_text):
    """
    Findings for one package.json: findings reported against the file itself, plus
    the CVEs of the npm packages it declares (deduplicated, capped).
    Raises ValueError if the file is not a JSON object.
    """
    package = json.loads(package_json_text)
    if not isinstance(package, dict):
        raise ValueError('package.json is not a JSON object')
    declared = set()
    for section in DEPENDENCY_SECTIONS:
        declared.update(package.get(section) or {})
    
    selected = []
    seen = set()
    for finding in all_findings:
        if repo_relative(clone_dir, finding.get('file')) == package_json_rel:
            selected.append(finding)
        elif finding['type'] == 'CVE' and finding.get('package') in declared:
            key = (finding.get('id'), finding.get('package'))
            if key not in seen:
                seen.add(key)
                selected.append(finding)
    return selected[:MAX_PACKAGE_FINDINGS]


def build_docker_image(repo_dir, dockerfile_rel, tag):
    """
    Build one Dockerfile with its own directory as the build context.

    Returns:
        The finished subprocess (check returncode / stderr).
    """
    dockerfile = os.path.join(repo_dir, dockerfile_rel)
    context = os.path.dirname(dockerfile)
    return subprocess.run(
        ["docker", "build", "-f", dockerfile, "-t", tag, context],
        capture_output=True,
        text=True
    )


def docker_failure_reason(stderr):
    """Short, secret-free reason for a failed docker build (details stay in the server log)."""
    registry_match = re.search(r'\b(registry\.redhat\.io)\b', stderr)
    if registry_match and ('401' in stderr or 'nauthorized' in stderr):
        return (f'Docker is not logged in to {registry_match.group(1)}. '
                f'Run "docker login {registry_match.group(1)}" and scan again.')
    return 'see server log.'


def remove_docker_images(tags):
    """Best-effort removal of the images built during a scan."""
    for tag in tags:
        try:
            subprocess.run(["docker", "rmi", "-f", tag], capture_output=True, timeout=120)
        except (OSError, subprocess.SubprocessError):
            logger.warning('Could not remove image %s', tag)


def collect_js_sources(root):
    """Read the JavaScript files under `root`, skipping dependencies and VCS data."""
    sources = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ('node_modules', '.git')]
        for name in filenames:
            if name.endswith(('.js', '.mjs', '.cjs')):
                try:
                    sources.append(read_text(os.path.join(dirpath, name)))
                except (OSError, UnicodeDecodeError):
                    continue
    return sources


def check_fixed_package_json(package_json_path, original_text):
    """
    Check that the remediated package.json will not break the application.

    - every dependency version the AI changed must exist in the npm registry
    - no JavaScript file may require() a package that is no longer declared

    Returns:
        A list of problems (empty if the file is fine).
    """
    problems = []

    original = json.loads(original_text)
    fixed = json.loads(read_text(package_json_path))

    all_deps = {}
    for section in DEPENDENCY_SECTIONS:
        all_deps.update(fixed.get(section, {}))

    changed = {
        name: version
        for name, version in fixed.get('dependencies', {}).items()
        if original.get('dependencies', {}).get(name) != version
    }

    # Without npm the registry cannot be queried, so skip rather than reject good fixes
    if npm_available():
        for name, version in changed.items():
            if not validate_npm_package(name, version):
                problems.append(f'{name}@{version} was not found in the npm registry')

    missing = find_missing_node_dependencies(
        collect_js_sources(os.path.dirname(package_json_path)),
        all_deps
    )
    if missing:
        problems.append(f'code requires packages missing from package.json: {", ".join(missing)}')

    return problems


def set_pr_result(scan_id, status, message, pr_url=None):
    """Record the outcome of the PR step (short, safe text only) and report it to the UI."""
    scan_results[scan_id]['pr_url'] = pr_url
    scan_results[scan_id]['pr_status'] = status
    scan_results[scan_id]['pr_message'] = message
    emit_progress(scan_id, STEP_PR, 'success' if pr_url else 'info', message,
                  {'pr_url': pr_url, 'detail': f'({pr_url})' if pr_url else ''})


def raise_pull_request(scan_id, repo_url, clone_dir, branch, base, files_updated,
                       metrics, all_findings, jira_keys):
    """
    Branch, commit only the changed files, push and open a PR against the base branch.

    This never raises: whatever goes wrong is logged server-side (token removed) and
    reported with a short message, so the scan itself still completes.
    """
    emit_progress(scan_id, STEP_PR, 'running', 'Raising pull request...')
    token = os.getenv('GITHUB_TOKEN')
    phase = 'preparing'
    try:
        if not files_updated:
            set_pr_result(scan_id, 'no_changes', 'No changes to commit, so no pull request was raised')
            return
        if not token:
            set_pr_result(scan_id, 'no_token', 'GITHUB_TOKEN is not set, so no pull request was raised')
            return
        try:
            parse_github_repo(repo_url)
        except UnsupportedRepositoryHost:
            set_pr_result(scan_id, 'unsupported_host',
                          'Pull requests are only supported for GitHub repositories')
            return
        validate_branch_name(branch)
        validate_branch_name(base)

        phase = 'commit'
        create_branch(clone_dir, branch)
        commit_changes(clone_dir, 'Security remediation: fix vulnerabilities and misconfigurations',
                       paths=files_updated)

        phase = 'push'
        emit_progress(scan_id, STEP_PR, 'running', f'Pushing branch {branch}...')
        push_branch(clone_dir, branch, token)

        phase = 'pull request'
        pr_url = create_pull_request(
            repo_url,
            branch,
            'Security remediation: fix vulnerabilities and misconfigurations',
            generate_remediation_pr_body(files_updated, metrics, all_findings, jira_keys),
            token,
            base=base
        )
        set_pr_result(scan_id, 'created', f'Pull request created: {pr_url}', pr_url)
        log_activity('Pull request created')
    except Exception as e:
        logger.error('[%s] Pull request step failed during %s: %s', scan_id, phase,
                     scrub_secrets(str(e), token))
        reasons = {
            'commit': 'Could not create the branch or commit (see server log)',
            'push': 'Could not push the branch (check that the token has write access); no pull request was created',
            'pull request': 'The branch was pushed but the pull request could not be created (see server log)',
        }
        status = {'commit': 'commit_failed', 'push': 'push_failed'}.get(phase, 'failed')
        set_pr_result(scan_id, status, reasons.get(phase, 'Could not prepare the pull request (see server log)'))


def get_jira_base_url():
    """
    Base URL used by the UI to build ticket links (<base>/browse/<KEY>).

    Only returned when JIRA is configured and JIRA_URL is plain https without embedded
    credentials, query or fragment. Otherwise None, and the UI shows keys as text.
    """
    raw = os.getenv('JIRA_URL', '').strip()
    if not raw or not is_jira_configured() or re.search(r'[\s\x00-\x1f\x7f]', raw):
        return None
    try:
        parsed = urlparse(raw)
        if (parsed.scheme != 'https' or not parsed.hostname
                or parsed.username is not None or parsed.password is not None):
            return None
        return f'https://{parsed.netloc}{parsed.path.rstrip("/")}'
    except ValueError:
        return None


def set_jira_link_result(scan_id, status, message, links=None):
    """Record the outcome of the JIRA link step (short, safe text only) and report it to the UI."""
    links = links or {}
    scan_results[scan_id]['jira_links'] = links
    scan_results[scan_id]['jira_link_message'] = message
    emit_progress(scan_id, STEP_JIRA_LINK, status, message, {
        'links': links,
        'detail': f'({", ".join(links)})' if links else ''
    })


def build_jira_summary(metrics, files_updated):
    """Short plain-text comment for a ticket: what was fixed and where."""
    labels = {'kubernetes': 'Kubernetes', 'cve': 'CVE', 'sast': 'SAST', 'secrets': 'Secrets', 'total': 'Total'}
    lines = ['Automated security remediation pull request raised.']
    for name, label in labels.items():
        m = metrics.get(name)
        if m:
            lines.append(f"{label}: {m['before']} -> {m['after']} ({m['fixed']} fixed)")
    if files_updated:
        shown = ', '.join(files_updated[:10])
        extra = f' (+{len(files_updated) - 10} more)' if len(files_updated) > 10 else ''
        lines.append(f'Files changed: {shown}{extra}')
    return '\n'.join(lines)


def link_pr_to_jira_tickets(scan_id, pr_url, jira_keys, metrics, files_updated):
    """
    Add the PR link and a summary comment to every JIRA ticket created in step 12.

    This never raises: one ticket failing does not stop the others, and the scan
    always continues. Only short, safe messages reach the UI.
    """
    scan_results[scan_id]['jira_links'] = {}
    scan_results[scan_id]['jira_link_message'] = ''
    try:
        if not pr_url:
            set_jira_link_result(scan_id, 'info', 'No pull request was raised, so no JIRA tickets were linked')
            return
        if not jira_keys:
            set_jira_link_result(scan_id, 'info', 'No JIRA tickets to link to the pull request')
            return
        if not is_jira_configured():
            set_jira_link_result(scan_id, 'info', 'JIRA is not configured, so the pull request was not linked')
            return

        emit_progress(scan_id, STEP_JIRA_LINK, 'running', 'Linking the pull request to JIRA tickets...')
        summary = build_jira_summary(metrics, files_updated)
        links = {}
        for key in jira_keys:
            try:
                links[key] = bool(link_pr_to_ticket(key, pr_url, summary))
            except Exception as e:
                logger.error('[%s] Linking the PR to a JIRA ticket failed: %s', scan_id, type(e).__name__)
                links[key] = False

        linked = sum(1 for ok in links.values() if ok)
        message = f'Linked the pull request to {linked} of {len(links)} JIRA tickets'
        if linked < len(links):
            message += ' (see server log for failures)'
        set_jira_link_result(scan_id, 'success' if linked else 'info', message, links)
    except Exception as e:
        logger.error('[%s] JIRA link step failed: %s', scan_id, type(e).__name__)
        set_jira_link_result(scan_id, 'info', 'Could not link the pull request to JIRA tickets (see server log)')


def run_security_scan(repo_url, scan_id):
    """Run the security scan workflow with progress updates."""
    clone_dir = None
    built_images = []
    try:
        # Fail fast: remediation needs Bob, so don't spend minutes scanning without it
        ensure_bob_configured()

        emit_progress(scan_id, STEP_CLEANUP, 'running', f'Starting security scan for {repo_url}')
        
        # Step 0: Cleanup of clones left behind by earlier scans
        emit_progress(scan_id, STEP_CLEANUP, 'running', 'Cleaning up previous clones...')
        cleanup_stale_clones()
        emit_progress(scan_id, STEP_CLEANUP, 'success', 'Cleanup complete')
        
        # Step 1: Get repository configuration
        emit_progress(scan_id, STEP_CONFIG, 'running', 'Getting repository configuration...')
        config = get_repository_config(repo_url)
        emit_progress(scan_id, STEP_CONFIG, 'success', f'Configuration loaded: {config["repo_name"]}', {
            'repo_name': config['repo_name'],
            'branch': config['branch'],
            'detail': f'({config["repo_name"]})'
        })
        
        # Step 2: Clone repository (into this scan's own directory)
        emit_progress(scan_id, STEP_CLONE, 'running', f'Cloning repository: {repo_url}')
        clone_dir = os.path.abspath(config['clone_dir'])
        clone_dir = clone_repository(repo_url, clone_dir)
        default_branch = get_default_branch(clone_dir)
        scan_results[scan_id]['default_branch'] = default_branch
        emit_progress(scan_id, STEP_CLONE, 'success', f'Repository cloned (default branch: {default_branch})', {
            'default_branch': default_branch
        })
        
        # Step 3: Find files anywhere in the repository
        emit_progress(scan_id, STEP_DISCOVER, 'running', 'Discovering files...')
        discovered = discover_repo_files(clone_dir)
        manifests = discovered['k8s_manifests']
        dockerfiles = discovered['dockerfiles']
        package_jsons = discovered['package_jsons']
        
        files_found = manifests + dockerfiles + package_jsons
        summary = (f'{len(manifests)} Kubernetes manifest(s), {len(dockerfiles)} Dockerfile(s), '
                   f'{len(package_jsons)} package.json file(s)')
        
        emit_progress(scan_id, STEP_DISCOVER, 'success', f'Found {len(files_found)} files: {summary}', {
            'files': files_found,
            'k8s_manifests': manifests,
            'dockerfiles': dockerfiles,
            'package_jsons': package_jsons,
            'detail': f'({summary})' if files_found else ''
        })
        
        # Step 4: Scan every Kubernetes manifest; each finding carries its repo-relative file
        emit_progress(scan_id, STEP_K8S, 'running', 'Scanning Kubernetes configurations...')
        k8s_findings = []
        scanned_manifests = set()
        if manifests:
            for manifest in manifests:
                try:
                    manifest_findings = summarize_findings(
                        scan_k8s_config(os.path.join(clone_dir, manifest))
                    )
                except Exception:
                    logger.exception('[%s] Kubernetes scan of %s failed', scan_id, manifest)
                    emit_progress(scan_id, STEP_K8S, 'info', f'Could not scan {manifest} (see server log)')
                    continue
                for finding in manifest_findings:
                    finding['file'] = manifest
                k8s_findings.extend(manifest_findings)
                scanned_manifests.add(manifest)
            
            if scanned_manifests:
                emit_progress(scan_id, STEP_K8S, 'success',
                              f'Found {len(k8s_findings)} Kubernetes issues in {len(scanned_manifests)} manifest(s)', {
                    'count': len(k8s_findings),
                    'detail': f'({len(k8s_findings)} issues)'
                })
                log_activity('Kubernetes scan completed')
            else:
                emit_progress(scan_id, STEP_K8S, 'info', 'No Kubernetes manifest could be scanned')
        else:
            emit_progress(scan_id, STEP_K8S, 'info', 'No Kubernetes manifests found')
        
        # Step 5: Build and scan a container image per Dockerfile
        emit_progress(scan_id, STEP_IMAGE, 'running', 'Building and scanning container images...')
        cve_findings = []
        scanned_dockerfiles = set()
        if dockerfiles:
            for index, dockerfile in enumerate(dockerfiles):
                # Unique per Dockerfile and per scan (image_name carries a random suffix)
                tag = f"{config['image_name']}-{index}"
                emit_progress(scan_id, STEP_IMAGE, 'running', f'Building {dockerfile}...')
                build = build_docker_image(clone_dir, dockerfile, tag)
                if build.returncode != 0:
                    logger.error('[%s] docker build of %s failed:\n%s',
                                 scan_id, dockerfile, build.stderr[-2000:])
                    emit_progress(scan_id, STEP_IMAGE, 'info',
                                  f'Could not build {dockerfile}, so it was not scanned. '
                                  f'{docker_failure_reason(build.stderr)}')
                    continue
                built_images.append(tag)
                
                try:
                    image_findings = summarize_cves(scan_image(tag))
                except Exception:
                    logger.exception('[%s] Image scan of %s failed', scan_id, dockerfile)
                    emit_progress(scan_id, STEP_IMAGE, 'info', f'Could not scan the image of {dockerfile} (see server log)')
                    continue
                for finding in image_findings:
                    finding['file'] = dockerfile
                    finding['image'] = tag
                cve_findings.extend(image_findings)
                scanned_dockerfiles.add(dockerfile)
            
            if scanned_dockerfiles:
                emit_progress(scan_id, STEP_IMAGE, 'success',
                              f'Found {len(cve_findings)} CVEs in {len(scanned_dockerfiles)} of {len(dockerfiles)} container image(s)', {
                    'cve_count': len(cve_findings),
                    'total_findings': len(cve_findings),
                    'detail': f'({len(cve_findings)} CVEs)'
                })
                log_activity('Container CVE scan completed')
            else:
                emit_progress(scan_id, STEP_IMAGE, 'info', 'No container image could be built and scanned')
        else:
            emit_progress(scan_id, STEP_IMAGE, 'info', 'No Dockerfile found, skipping image scan')
        
        # Steps 6-10: Additional scanners
        sast_findings, sast_ran = run_optional_scan(
            scan_id, STEP_SAST, 'SAST scan',
            lambda: summarize_sast(scan_code(clone_dir))
        )
        secret_findings, secrets_ran = run_optional_scan(
            scan_id, STEP_SECRETS, 'Secret scan',
            lambda: summarize_secrets(scan_secrets(clone_dir))
        )
        cspm_findings, _ = run_optional_scan(
            scan_id, STEP_CSPM, 'Cloud posture scan',
            lambda: summarize_cspm(scan_cspm(clone_dir))
        )
        # Runtime events and live network exposure come from a running cluster or
        # cloud account, so a repository scan has nothing to check for them
        emit_progress(scan_id, STEP_RUNTIME, 'info',
                      'Runtime security is not applicable to a repository scan (needs a running workload)')
        emit_progress(scan_id, STEP_NETWORK, 'info',
                      'Network exposure is not applicable to a repository scan (needs a live environment)')
        
        # Step 11: Combine findings
        emit_progress(scan_id, STEP_COMBINE, 'running', 'Combining security findings...')
        all_findings = combine_findings(
            k8s_findings,
            cve_findings,
            sast_findings,
            secret_findings,
            cspm_findings
        )
        total_issues = len(all_findings)
        emit_progress(scan_id, STEP_COMBINE, 'success', f'Total issues found: {total_issues}', {
            'total': total_issues,
            'k8s': len(k8s_findings),
            'cve': len(cve_findings),
            'sast': len(sast_findings),
            'secrets': len(secret_findings),
            'cspm': len(cspm_findings),
            'detail': (
                f'(K8s: {len(k8s_findings)}, CVE: {len(cve_findings)}, '
                f'SAST: {len(sast_findings)}, Secrets: {len(secret_findings)}, '
                f'Cloud posture: {len(cspm_findings)})'
            )
        })
        log_activity('Unified findings generated')
        
        # Step 12: Create JIRA tickets (critical / high findings only)
        emit_progress(scan_id, STEP_JIRA, 'running', 'Creating JIRA tickets...')
        jira_keys = []
        try:
            important = [f for f in all_findings if f.get('severity') in JIRA_SEVERITIES]
            for finding in important[:5]:  # Limit to first 5
                key = create_jira_ticket(finding, repo_url)
                if key:
                    jira_keys.append(key)
            emit_progress(scan_id, STEP_JIRA, 'success', f'Created {len(jira_keys)} JIRA tickets', {
                'tickets': jira_keys,
                'detail': f'({", ".join(jira_keys)})' if jira_keys else ''
            })
        except Exception as e:
            emit_progress(scan_id, STEP_JIRA, 'info', f'JIRA integration not configured: {str(e)}')
        # Kept for the PR body and for linking the PR to the tickets
        scan_results[scan_id]['jira_keys'] = list(jira_keys)
        jira_base_url = get_jira_base_url()
        if jira_base_url:
            scan_results[scan_id]['jira_base_url'] = jira_base_url
        
        # Step 13: Generate remediation per Kubernetes manifest and per package.json.
        # Each call only gets that file's findings; a failure only skips that file.
        emit_progress(scan_id, STEP_REMEDIATE, 'running', 'Generating AI-powered remediation...')
        
        originals = {}       # repo-relative path -> original text (for revert)
        fixed_contents = {}  # repo-relative path -> fixed text from the AI
        
        for manifest in manifests:
            manifest_findings = [f for f in all_findings
                                 if f['type'] == 'MISCONFIG' and f.get('file') == manifest]
            if not manifest_findings:
                continue
            emit_progress(scan_id, STEP_REMEDIATE, 'running', f'Remediating {manifest}...')
            try:
                original = read_text(os.path.join(clone_dir, manifest))
                reply = generate_remediation(json.dumps(manifest_findings, indent=2), original, None)
                fixed = extract_fixed_content(reply, "===FIXED_DEPLOYMENT===")
            except Exception:
                logger.exception('[%s] Remediation of %s failed', scan_id, manifest)
                emit_progress(scan_id, STEP_REMEDIATE, 'info',
                              f'{manifest} left unchanged: remediation failed (see server log)')
                continue
            if not fixed:
                logger.warning('[%s] Remediation reply for %s was empty', scan_id, manifest)
                emit_progress(scan_id, STEP_REMEDIATE, 'info',
                              f'{manifest} left unchanged: the AI reply did not contain a fixed file')
                continue
            originals[manifest] = original
            fixed_contents[manifest] = fixed
        
        # package.json is npm-only. Its findings are the image CVEs of the packages it
        # declares, so repos without package.json (Python, Java, Go, ...) skip this cleanly.
        for package_json_rel in package_jsons:
            try:
                original = read_text(os.path.join(clone_dir, package_json_rel))
                package_findings = package_json_findings(clone_dir, all_findings, package_json_rel, original)
                if not package_findings:
                    continue
                emit_progress(scan_id, STEP_REMEDIATE, 'running', f'Remediating {package_json_rel}...')
                reply = generate_remediation(json.dumps(package_findings, indent=2), None, original)
                fixed = extract_fixed_content(reply, "===FIXED_PACKAGE_JSON===")
            except Exception:
                logger.exception('[%s] Remediation of %s failed', scan_id, package_json_rel)
                emit_progress(scan_id, STEP_REMEDIATE, 'info',
                              f'{package_json_rel} left unchanged: remediation failed (see server log)')
                continue
            if not fixed:
                logger.warning('[%s] Remediation reply for %s was empty', scan_id, package_json_rel)
                emit_progress(scan_id, STEP_REMEDIATE, 'info',
                              f'{package_json_rel} left unchanged: the AI reply did not contain a fixed file')
                continue
            originals[package_json_rel] = original
            fixed_contents[package_json_rel] = fixed
        
        emit_progress(scan_id, STEP_REMEDIATE, 'success',
                      f'Remediation generated for {len(fixed_contents)} file(s)')
        log_activity('AI remediation generated')
        
        # Step 14: Apply fixes
        emit_progress(scan_id, STEP_APPLY, 'running', 'Applying security fixes...')
        files_updated = []  # repo-relative paths of every file that really changed
        
        for rel, fixed in fixed_contents.items():
            if fixed.strip() == originals[rel].strip():
                emit_progress(scan_id, STEP_APPLY, 'info', f'{rel} left unchanged: the AI made no changes')
                continue
            try:
                write_text(os.path.join(clone_dir, rel), fixed + '\n')
            except OSError:
                logger.exception('[%s] Could not write %s', scan_id, rel)
                emit_progress(scan_id, STEP_APPLY, 'info', f'{rel} left unchanged: could not be written')
                continue
            files_updated.append(rel)
        
        if originals and not files_updated:
            emit_progress(scan_id, STEP_APPLY, 'info', 'No files were changed: the fixed files could not be written.')
        else:
            emit_progress(scan_id, STEP_APPLY, 'success', f'Updated {len(files_updated)} files', {
                'files': files_updated,
                'detail': f'({", ".join(files_updated)})' if files_updated else ''
            })
        
        # Step 15: Fix SAST / hardcoded-secret findings in source files
        emit_progress(scan_id, STEP_SOURCE_FIX, 'running', 'Fixing code vulnerabilities and hardcoded secrets...')
        source_findings = [f for f in all_findings if f['type'] in ('SAST', 'SECRET')]
        source_updated = []
        if source_findings:
            try:
                source_result = apply_source_fixes(clone_dir, source_findings)
                source_updated = source_result['updated']
                files_updated.extend(f for f in source_updated if f not in files_updated)
                skipped = len(source_result['skipped'])
                emit_progress(scan_id, STEP_SOURCE_FIX, 'success',
                              f'Updated {len(source_updated)} source files ({skipped} left unchanged)', {
                    'files': source_updated,
                    'detail': f'({", ".join(source_updated)})' if source_updated else ''
                })
                log_activity('Source code remediation completed')
            except Exception:
                logger.exception("Source code remediation failed")
                emit_progress(scan_id, STEP_SOURCE_FIX, 'info', 'Source code remediation skipped: it failed (see server log)')
        else:
            emit_progress(scan_id, STEP_SOURCE_FIX, 'info', 'No code or secret findings to fix')
        
        # Step 16: Advisory for findings that cannot be fixed in the repository
        emit_progress(scan_id, STEP_ADVISORY, 'running', 'Generating posture recommendations...')
        posture_findings = [f for f in all_findings if f['type'] == 'CSPM']
        if posture_findings:
            try:
                generate_advisory(posture_findings)
                emit_progress(scan_id, STEP_ADVISORY, 'success',
                              f'Recommendations written for {len(posture_findings)} findings (reports/advisory.md)', {
                    'count': len(posture_findings),
                    'detail': f'({len(posture_findings)} findings)'
                })
            except Exception:
                logger.exception("Advisory generation failed")
                emit_progress(scan_id, STEP_ADVISORY, 'info', 'Advisory skipped: it failed (see server log)')
        else:
            emit_progress(scan_id, STEP_ADVISORY, 'info', 'No cloud posture findings')
        
        # Step 17: Validate every fixed file. A file that fails is restored to its
        # original content and does not affect the others.
        emit_progress(scan_id, STEP_VALIDATE, 'running', 'Validating fixed files...')
        validation_results = {}
        
        def revert_file(rel, reason):
            write_text(os.path.join(clone_dir, rel), originals[rel])
            files_updated.remove(rel)
            validation_results.setdefault('reverted', []).append({'file': rel, 'reason': reason})
            emit_progress(scan_id, STEP_VALIDATE, 'info', f'{rel} changes reverted: {reason}')
        
        for rel in [f for f in files_updated if f in manifests]:
            path = os.path.join(clone_dir, rel)
            # A reply that is valid YAML but not a manifest (e.g. prose) must not be kept
            if not (validate_yaml(path) and is_k8s_manifest(path)):
                revert_file(rel, 'the fixed file is not a valid Kubernetes manifest')
        
        for rel in [f for f in files_updated if f in package_jsons]:
            path = os.path.join(clone_dir, rel)
            if not validate_package_json(path):
                revert_file(rel, 'the fixed file is not valid JSON')
                continue
            try:
                problems = check_fixed_package_json(path, originals[rel])
            except Exception:
                logger.exception('[%s] Dependency check of %s failed', scan_id, rel)
                problems = ['the dependency check failed (see server log)']
            if problems:
                # Keep the original rather than ship a package.json that breaks the app
                revert_file(rel, '; '.join(problems))
        
        validation_results['validated'] = [f for f in files_updated if f in manifests or f in package_jsons]
        emit_progress(scan_id, STEP_VALIDATE, 'success',
                      f'Validated {len(validation_results["validated"])} fixed file(s)', validation_results)
        
        # Step 18: Remediate every Dockerfile that was scanned; a failure only affects that file
        emit_progress(scan_id, STEP_DOCKERFILE, 'running', 'Updating Dockerfiles for CVE fixes...')
        dockerfile_originals = {}  # Dockerfiles that were changed -> original text (for revert)
        if dockerfiles:
            for dockerfile in dockerfiles:
                if dockerfile not in scanned_dockerfiles:
                    continue
                dockerfile_findings = [f for f in all_findings
                                       if f['type'] == 'CVE' and f.get('file') == dockerfile]
                if not dockerfile_findings:
                    emit_progress(scan_id, STEP_DOCKERFILE, 'info', f'No CVEs to fix in {dockerfile}')
                    continue
                emit_progress(scan_id, STEP_DOCKERFILE, 'running', f'Updating {dockerfile}...')
                dockerfile_path = os.path.join(clone_dir, dockerfile)
                try:
                    original = read_text(dockerfile_path)
                    fixed_dockerfile = generate_dockerfile_remediation(original, dockerfile_findings[:10])
                    if fixed_dockerfile.strip() == original.strip():
                        emit_progress(scan_id, STEP_DOCKERFILE, 'info', f'{dockerfile} left unchanged')
                        continue
                    write_text(dockerfile_path, fixed_dockerfile + '\n')
                except Exception as e:
                    logger.warning('[%s] Dockerfile remediation of %s failed: %s', scan_id, dockerfile, e)
                    emit_progress(scan_id, STEP_DOCKERFILE, 'info',
                                  f'{dockerfile} left unchanged: remediation failed (see server log)')
                    continue
                dockerfile_originals[dockerfile] = original
            
            if dockerfile_originals:
                emit_progress(scan_id, STEP_DOCKERFILE, 'success', f'Updated {len(dockerfile_originals)} Dockerfile(s)', {
                    'files': list(dockerfile_originals),
                    'detail': f'({", ".join(dockerfile_originals)})'
                })
            else:
                emit_progress(scan_id, STEP_DOCKERFILE, 'info', 'No Dockerfile was changed')
        else:
            emit_progress(scan_id, STEP_DOCKERFILE, 'info', 'No Dockerfile found')
        
        # Step 19: Rebuild each changed Dockerfile with its own context
        emit_progress(scan_id, STEP_REBUILD, 'running', 'Rebuilding container images...')
        new_cve_findings = []
        rebuilt = 0
        for index, dockerfile in enumerate(dockerfiles):
            if dockerfile not in scanned_dockerfiles:
                continue
            old_findings = [f for f in cve_findings if f['file'] == dockerfile]
            if dockerfile not in dockerfile_originals:
                # Same Dockerfile, same image: its CVEs are unchanged
                new_cve_findings.extend(old_findings)
                continue
            
            fixed_tag = f"{config['image_name']}-{index}-fixed"
            built_images.append(fixed_tag)
            emit_progress(scan_id, STEP_REBUILD, 'running', f'Rebuilding {dockerfile}...')
            build_error = None
            try:
                build = build_docker_image(clone_dir, dockerfile, fixed_tag)
                if build.returncode != 0:
                    logger.error('[%s] docker build of %s failed:\n%s',
                                 scan_id, dockerfile, build.stderr[-2000:])
                    build_error = docker_failure_reason(build.stderr)
            except Exception:
                logger.exception('[%s] docker build of %s failed', scan_id, dockerfile)
                build_error = 'see server log.'
            
            if build_error:
                # Do not leave a Dockerfile that does not build in the repository,
                # and do not claim any CVE improvement that was never verified
                write_text(os.path.join(clone_dir, dockerfile), dockerfile_originals[dockerfile])
                new_cve_findings.extend(old_findings)
                emit_progress(scan_id, STEP_REBUILD, 'info',
                              f'Rebuild of {dockerfile} failed, so the Dockerfile change was reverted. '
                              f'{build_error} CVE count is unchanged.')
                continue
            
            rebuilt += 1
            files_updated.append(dockerfile)
            try:
                new_cve_findings.extend(summarize_cves(scan_image(fixed_tag)))
            except Exception:
                logger.exception('[%s] Image scan of rebuilt %s failed', scan_id, dockerfile)
                new_cve_findings.extend(old_findings)
                emit_progress(scan_id, STEP_REBUILD, 'info',
                              f'Could not scan the rebuilt image of {dockerfile} (see server log). '
                              'CVE count is unchanged.')
        
        if rebuilt:
            emit_progress(scan_id, STEP_REBUILD, 'success',
                          f'Rebuilt {rebuilt} of {len(dockerfile_originals)} changed Dockerfile(s). '
                          f'New CVE count: {len(new_cve_findings)}', {
                'new_cve_count': len(new_cve_findings),
                'detail': f'({len(new_cve_findings)} CVEs remaining)'
            })
            log_activity('Docker image rebuilt and re-scanned')
        elif dockerfile_originals:
            emit_progress(scan_id, STEP_REBUILD, 'info',
                          'No rebuilt image could be verified; all Dockerfile changes were reverted')
        else:
            emit_progress(scan_id, STEP_REBUILD, 'info', 'No Dockerfile to rebuild')
        
        # The list of changed files is final here (needed to commit only these files)
        files_updated = sorted(set(files_updated))
        scan_results[scan_id]['files_updated'] = files_updated
        
        # Step 20: Re-scan every Kubernetes manifest (images were re-scanned in step 19)
        emit_progress(scan_id, STEP_RESCAN, 'running', 'Re-scanning fixed assets...')
        new_k8s_findings = []
        for manifest in manifests:
            if manifest not in scanned_manifests:
                continue
            try:
                rescanned = summarize_findings(scan_k8s_config(os.path.join(clone_dir, manifest)))
            except Exception:
                logger.exception('[%s] Kubernetes re-scan of %s failed', scan_id, manifest)
                emit_progress(scan_id, STEP_RESCAN, 'info', f'Could not re-scan {manifest} (see server log)')
                new_k8s_findings.extend(f for f in k8s_findings if f['file'] == manifest)
                continue
            for finding in rescanned:
                finding['file'] = manifest
            new_k8s_findings.extend(rescanned)
        
        # If a re-scan cannot run, the category is left out of the metrics
        # instead of reporting a false 100% improvement
        new_sast_findings = sast_findings
        if sast_ran:
            new_sast_findings, sast_ran = run_optional_scan(
                scan_id, STEP_RESCAN, 'SAST re-scan',
                lambda: summarize_sast(scan_code(clone_dir))
            )
        
        new_secret_findings = secret_findings
        if secrets_ran:
            new_secret_findings, secrets_ran = run_optional_scan(
                scan_id, STEP_RESCAN, 'Secret re-scan',
                lambda: summarize_secrets(scan_secrets(clone_dir))
            )
        
        emit_progress(scan_id, STEP_RESCAN, 'success', 'Re-scan complete', {
            'new_k8s_count': len(new_k8s_findings),
            'new_cve_count': len(new_cve_findings),
            'new_sast_count': len(new_sast_findings),
            'new_secret_count': len(new_secret_findings),
            'detail': (
                f'(K8s: {len(new_k8s_findings)}, CVE: {len(new_cve_findings)}, '
                f'SAST: {len(new_sast_findings)}, Secrets: {len(new_secret_findings)})'
            )
        })
        
        # Step 21: Calculate metrics
        emit_progress(scan_id, STEP_METRICS, 'running', 'Calculating improvement metrics...')
        
        metrics = {
            'kubernetes': metric(len(k8s_findings), len(new_k8s_findings)),
            'cve': metric(len(cve_findings), len(new_cve_findings))
        }
        if sast_ran:
            metrics['sast'] = metric(len(sast_findings), len(new_sast_findings))
        if secrets_ran:
            metrics['secrets'] = metric(len(secret_findings), len(new_secret_findings))
        
        # Cloud / runtime / network issues are advisory only, so they are not
        # part of the before/after total
        metrics['total'] = metric(
            sum(m['before'] for m in metrics.values()),
            sum(m['after'] for m in metrics.values())
        )
        metrics['advisory'] = {
            'cspm': len(cspm_findings)
        }
        
        emit_progress(scan_id, STEP_METRICS, 'success', 'Scan complete!', metrics)
        log_activity('Security summary generated')
        
        # Step 22: Raise the PR. It must happen here, before the clone is removed, and a
        # failure is only reported: it never fails the scan.
        raise_pull_request(scan_id, repo_url, clone_dir, config['branch'],
                           scan_results[scan_id]['default_branch'], files_updated,
                           metrics, all_findings, jira_keys)
        
        # Step 23: Attach the PR to the JIRA tickets (failures are only reported)
        link_pr_to_jira_tickets(scan_id, scan_results[scan_id].get('pr_url'),
                                jira_keys, metrics, files_updated)
        
        # Mark as complete
        scan_results[scan_id]['status'] = 'complete'
        scan_results[scan_id]['metrics'] = metrics
        
    except Exception as e:
        logger.exception('[%s] Scan failed', scan_id)
        emit_progress(scan_id, -1, 'error', f'Error: {str(e)}')
        scan_results[scan_id]['status'] = 'error'
        scan_results[scan_id]['error'] = str(e)
    finally:
        # Every scan removes its own clone and images, whether it succeeded or not
        if clone_dir:
            cleanup_cloned_repo(clone_dir)
        remove_docker_images(built_images)


@app.route('/')
def index():
    """Render the main page."""
    return render_template('index.html', steps=STEPS)


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new security scan."""
    data = request.json
    repo_url = data.get('repo_url')
    
    if not repo_url:
        return jsonify({'error': 'Repository URL is required'}), 400
    
    try:
        repo_url = validate_repo_url(repo_url)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    
    # Generate scan ID
    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # Start scan in background thread
    thread = threading.Thread(target=run_security_scan, args=(repo_url, scan_id))
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'scan_id': scan_id,
        'status': 'started',
        'message': 'Security scan started'
    })


@app.route('/api/scan/<scan_id>')
def get_scan_status(scan_id):
    """Get the status of a scan."""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scan_results[scan_id])


@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    print('Client connected')


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    print('Client disconnected')


@socketio.on('join_scan')
def handle_join_scan(data):
    """Join a scan room for updates."""
    scan_id = data.get('scan_id')
    if scan_id:
        from flask_socketio import join_room
        join_room(scan_id)
        emit('joined', {'scan_id': scan_id})


def log_startup_config():
    """Log which settings are configured. Names only - values are never logged."""
    settings = ('BOB_API_KEY', 'GITHUB_TOKEN', 'JIRA_URL', 'JIRA_EMAIL', 'JIRA_API_TOKEN')
    for name in settings:
        if os.getenv(name):
            logger.info('Config %-22s set', name)
        else:
            logger.warning('Config %-22s NOT set', name)


if __name__ == '__main__':
    port = int(os.getenv('PORT', 8000))
    host = os.getenv('HOST', '127.0.0.1')
    log_startup_config()
    logger.info('Starting AudeSec web UI on http://%s:%s', host, port)
    socketio.run(app, debug=False, host=host, port=port)
