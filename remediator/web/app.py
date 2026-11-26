from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import threading
import os
import subprocess
import logging
from datetime import datetime
import json

from remediator.config import get_repository_config
from remediator.integrations.git_operations import clone_repository, cleanup_cloned_repo
from remediator.scanners.scanner import scan_k8s_config, summarize_findings
from remediator.scanners.image_scanner import scan_image, summarize_cves
from remediator.scanners.sast_scanner import scan_code, summarize_sast
from remediator.scanners.secret_scanner import scan_secrets, summarize_secrets
from remediator.scanners.cspm_scanner import scan_cspm, summarize_cspm
from remediator.scanners.runtime_scanner import scan_runtime, summarize_runtime
from remediator.scanners.network_scanner import scan_network, summarize_network
from remediator.findings import combine_findings
from remediator.integrations.jira_agent import create_jira_ticket
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
from remediator.scanners.feed_loader import FeedNotConfigured
from remediator.logger import log_activity

logger = logging.getLogger(__name__)

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

STEPS = [
    (STEP_CLEANUP, "🧹", "Cleanup", "Preparing environment..."),
    (STEP_CONFIG, "⚙️", "Configuration", "Loading repository configuration..."),
    (STEP_CLONE, "📥", "Clone Repository", "Cloning repository..."),
    (STEP_DISCOVER, "🔍", "File Discovery", "Discovering files..."),
    (STEP_K8S, "☸️", "Kubernetes Scan", "Scanning Kubernetes configurations..."),
    (STEP_IMAGE, "🐳", "Container Scan", "Building and scanning container image..."),
    (STEP_SAST, "🧬", "SAST Scan", "Scanning source code for vulnerabilities..."),
    (STEP_SECRETS, "🔑", "Secret Scan", "Scanning for hardcoded secrets..."),
    (STEP_CSPM, "☁️", "CSPM Scan", "Checking cloud security posture..."),
    (STEP_RUNTIME, "🏃", "Runtime Security", "Checking runtime security events..."),
    (STEP_NETWORK, "🌐", "Network Exposure", "Checking network exposure..."),
    (STEP_COMBINE, "📊", "Combine Findings", "Analyzing security findings..."),
    (STEP_JIRA, "🎫", "JIRA Tickets", "Creating tracking tickets..."),
    (STEP_REMEDIATE, "🤖", "AI Remediation", "Generating fixes with AI..."),
    (STEP_APPLY, "✏️", "Apply Fixes", "Applying security fixes..."),
    (STEP_SOURCE_FIX, "🛠️", "Source Code Fixes", "Fixing code vulnerabilities and secrets..."),
    (STEP_ADVISORY, "📝", "Posture Advisory", "Recommending cloud, runtime and network fixes..."),
    (STEP_VALIDATE, "✅", "Validation", "Validating fixed files..."),
    (STEP_DOCKERFILE, "🔧", "Dockerfile Update", "Updating Dockerfile..."),
    (STEP_REBUILD, "🔨", "Rebuild Container", "Rebuilding container image..."),
    (STEP_RESCAN, "🔄", "Re-scan", "Re-scanning fixed assets..."),
    (STEP_METRICS, "📈", "Metrics", "Calculating improvement metrics..."),
]

JIRA_SEVERITIES = ("HIGH", "CRITICAL")

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
    except FeedNotConfigured as e:
        emit_progress(scan_id, step, 'info', f'{label} skipped: {e}')
        return [], False
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


def run_security_scan(repo_url, scan_id):
    """Run the security scan workflow with progress updates."""
    try:
        emit_progress(scan_id, STEP_CLEANUP, 'running', f'Starting security scan for {repo_url}')
        
        # Step 0: Cleanup
        emit_progress(scan_id, STEP_CLEANUP, 'running', 'Cleaning up previous clones...')
        cleanup_cloned_repo()
        emit_progress(scan_id, STEP_CLEANUP, 'success', 'Cleanup complete')
        
        # Step 1: Get repository configuration
        emit_progress(scan_id, STEP_CONFIG, 'running', 'Getting repository configuration...')
        config = get_repository_config(repo_url)
        emit_progress(scan_id, STEP_CONFIG, 'success', f'Configuration loaded: {config["repo_name"]}', {
            'repo_name': config['repo_name'],
            'branch': config['branch'],
            'detail': f'({config["repo_name"]})'
        })
        
        # Step 2: Clone repository
        emit_progress(scan_id, STEP_CLONE, 'running', f'Cloning repository: {repo_url}')
        clone_dir = clone_repository(repo_url, config['branch'])
        emit_progress(scan_id, STEP_CLONE, 'success', f'Repository cloned to: {clone_dir}')
        
        # Step 3: Find files
        emit_progress(scan_id, STEP_DISCOVER, 'running', 'Discovering files...')
        deployment_path = os.path.join(clone_dir, config['deployment_file'])
        package_json_path = os.path.join(clone_dir, config['package_json_file'])
        dockerfile_path = os.path.join(clone_dir, config['dockerfile'])
        
        files_found = []
        if os.path.exists(deployment_path):
            files_found.append('deployment.yaml')
        if os.path.exists(package_json_path):
            files_found.append('package.json')
        if os.path.exists(dockerfile_path):
            files_found.append('Dockerfile')
        
        emit_progress(scan_id, STEP_DISCOVER, 'success', f'Found {len(files_found)} files', {
            'files': files_found,
            'detail': f'({", ".join(files_found)})' if files_found else ''
        })
        
        # Step 4: Scan Kubernetes configs
        emit_progress(scan_id, STEP_K8S, 'running', 'Scanning Kubernetes configurations...')
        k8s_findings = []
        if os.path.exists(deployment_path):
            scan_result = scan_k8s_config(deployment_path)
            k8s_findings = summarize_findings(scan_result)
            emit_progress(scan_id, STEP_K8S, 'success', f'Found {len(k8s_findings)} Kubernetes issues', {
                'count': len(k8s_findings),
                'detail': f'({len(k8s_findings)} issues)'
            })
            log_activity('Kubernetes scan completed')
        else:
            emit_progress(scan_id, STEP_K8S, 'info', 'No Kubernetes files to scan')
        
        # Step 5: Build and scan container image
        emit_progress(scan_id, STEP_IMAGE, 'running', 'Building and scanning container image...')
        cve_findings = []
        if os.path.exists(dockerfile_path):
            # Build image first
            build_cmd = ["docker", "build", "-t", config['image_name'], clone_dir]
            subprocess.run(build_cmd, capture_output=True)
            
            # Scan image
            scan_result = scan_image(config['image_name'])
            cve_findings = summarize_cves(scan_result)
            emit_progress(scan_id, STEP_IMAGE, 'success', f'Found {len(cve_findings)} CVEs in container image', {
                'cve_count': len(cve_findings),
                'total_findings': len(cve_findings),
                'detail': f'({len(cve_findings)} CVEs)'
            })
            log_activity('Container CVE scan completed')
        else:
            emit_progress(scan_id, STEP_IMAGE, 'info', 'No Dockerfile to scan')
        
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
            scan_id, STEP_CSPM, 'CSPM scan',
            lambda: summarize_cspm(scan_cspm())
        )
        runtime_findings, _ = run_optional_scan(
            scan_id, STEP_RUNTIME, 'Runtime scan',
            lambda: summarize_runtime(scan_runtime())
        )
        network_findings, _ = run_optional_scan(
            scan_id, STEP_NETWORK, 'Network exposure scan',
            lambda: summarize_network(scan_network())
        )
        
        # Step 11: Combine findings
        emit_progress(scan_id, STEP_COMBINE, 'running', 'Combining security findings...')
        all_findings = combine_findings(
            k8s_findings,
            cve_findings,
            sast_findings,
            secret_findings,
            cspm_findings,
            runtime_findings,
            network_findings
        )
        total_issues = len(all_findings)
        emit_progress(scan_id, STEP_COMBINE, 'success', f'Total issues found: {total_issues}', {
            'total': total_issues,
            'k8s': len(k8s_findings),
            'cve': len(cve_findings),
            'sast': len(sast_findings),
            'secrets': len(secret_findings),
            'cspm': len(cspm_findings),
            'runtime': len(runtime_findings),
            'network': len(network_findings),
            'detail': (
                f'(K8s: {len(k8s_findings)}, CVE: {len(cve_findings)}, '
                f'SAST: {len(sast_findings)}, Secrets: {len(secret_findings)}, '
                f'CSPM: {len(cspm_findings)}, Runtime: {len(runtime_findings)}, '
                f'Network: {len(network_findings)})'
            )
        })
        log_activity('Unified findings generated')
        
        # Step 12: Create JIRA tickets (critical / high findings only)
        emit_progress(scan_id, STEP_JIRA, 'running', 'Creating JIRA tickets...')
        jira_keys = []
        try:
            important = [f for f in all_findings if f.get('severity') in JIRA_SEVERITIES]
            for finding in important[:5]:  # Limit to first 5
                key = create_jira_ticket(finding)
                if key:
                    jira_keys.append(key)
            emit_progress(scan_id, STEP_JIRA, 'success', f'Created {len(jira_keys)} JIRA tickets', {
                'tickets': jira_keys,
                'detail': f'({", ".join(jira_keys)})' if jira_keys else ''
            })
        except Exception as e:
            emit_progress(scan_id, STEP_JIRA, 'info', f'JIRA integration not configured: {str(e)}')
        
        # Step 13: Generate remediation for Kubernetes / dependency findings
        emit_progress(scan_id, STEP_REMEDIATE, 'running', 'Generating AI-powered remediation...')
        
        deployment_yaml = None
        package_json = None
        
        if os.path.exists(deployment_path):
            deployment_yaml = read_text(deployment_path)
        
        if os.path.exists(package_json_path):
            package_json = read_text(package_json_path)
        
        remediation = generate_remediation(
            json.dumps(
                [f for f in all_findings if f['type'] in ('MISCONFIG', 'CVE')],
                indent=2
            ),
            deployment_yaml,
            package_json
        )
        emit_progress(scan_id, STEP_REMEDIATE, 'success', 'Remediation generated')
        log_activity('AI remediation generated')
        
        # Step 14: Apply fixes
        emit_progress(scan_id, STEP_APPLY, 'running', 'Applying security fixes...')
        files_updated = []
        
        if deployment_yaml and "===FIXED_DEPLOYMENT===" in remediation:
            fixed_yaml = remediation.split("===FIXED_DEPLOYMENT===")[1]
            if "===FIXED_PACKAGE_JSON===" in fixed_yaml:
                fixed_yaml = fixed_yaml.split("===FIXED_PACKAGE_JSON===")[0]
            fixed_yaml = fixed_yaml.strip()
            
            with open(deployment_path, 'w') as f:
                f.write(fixed_yaml)
            files_updated.append('deployment.yaml')
        
        if package_json and "===FIXED_PACKAGE_JSON===" in remediation:
            fixed_json = remediation.split("===FIXED_PACKAGE_JSON===")[1].strip()
            with open(package_json_path, 'w') as f:
                f.write(fixed_json)
            files_updated.append('package.json')
        
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
        posture_findings = [f for f in all_findings if f['type'] in ('CSPM', 'RUNTIME', 'NETWORK')]
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
            emit_progress(scan_id, STEP_ADVISORY, 'info', 'No cloud, runtime or network findings')
        
        # Step 17: Validate fixes
        emit_progress(scan_id, STEP_VALIDATE, 'running', 'Validating fixed files...')
        validation_results = {}
        
        if 'deployment.yaml' in files_updated:
            yaml_valid = validate_yaml(deployment_path)
            validation_results['yaml'] = {'valid': yaml_valid, 'error': None if yaml_valid else 'Validation failed'}
        
        if 'package.json' in files_updated:
            json_valid = validate_package_json(package_json_path)
            validation_results['json'] = {'valid': json_valid, 'error': None if json_valid else 'Validation failed'}
            
            if json_valid:
                problems = check_fixed_package_json(package_json_path, package_json)
                if problems:
                    # Keep the original rather than ship a package.json that breaks the app
                    with open(package_json_path, 'w') as f:
                        f.write(package_json)
                    files_updated.remove('package.json')
                    validation_results['dependencies'] = {'valid': True, 'error': None, 'reverted': problems}
                    emit_progress(scan_id, STEP_VALIDATE, 'info',
                                  'package.json changes reverted: ' + '; '.join(problems))
        
        all_valid = all(v['valid'] for v in validation_results.values())
        
        if all_valid:
            emit_progress(scan_id, STEP_VALIDATE, 'success', 'All files validated successfully', validation_results)
        else:
            emit_progress(scan_id, STEP_VALIDATE, 'error', 'Validation failed', validation_results)
            scan_results[scan_id]['status'] = 'error'
            return
        
        # Step 18: Dockerfile remediation
        emit_progress(scan_id, STEP_DOCKERFILE, 'running', 'Updating Dockerfile for CVE fixes...')
        if os.path.exists(dockerfile_path):
            original_dockerfile = read_text(dockerfile_path)
            
            if cve_findings:
                fixed_dockerfile = generate_dockerfile_remediation(
                    original_dockerfile,
                    cve_findings[:10]
                )
                
                with open(dockerfile_path, 'w') as f:
                    f.write(fixed_dockerfile)
                
                emit_progress(scan_id, STEP_DOCKERFILE, 'success', 'Dockerfile updated')
            else:
                emit_progress(scan_id, STEP_DOCKERFILE, 'info', 'No CVEs to fix in Dockerfile')
        else:
            emit_progress(scan_id, STEP_DOCKERFILE, 'info', 'No Dockerfile found')
        
        # Step 19: Rebuild container
        emit_progress(scan_id, STEP_REBUILD, 'running', 'Rebuilding container image...')
        new_cve_findings = []
        if os.path.exists(dockerfile_path):
            # Build image
            build_cmd = ["docker", "build", "-t", f"{config['image_name']}-fixed", clone_dir]
            subprocess.run(build_cmd, capture_output=True)
            
            # Scan new image
            scan_result = scan_image(f"{config['image_name']}-fixed")
            new_cve_findings = summarize_cves(scan_result)
            emit_progress(scan_id, STEP_REBUILD, 'success', f'Rebuild complete. New CVE count: {len(new_cve_findings)}', {
                'new_cve_count': len(new_cve_findings),
                'detail': f'({len(new_cve_findings)} CVEs remaining)'
            })
            log_activity('Docker image rebuilt and re-scanned')
        else:
            emit_progress(scan_id, STEP_REBUILD, 'info', 'No Dockerfile to rebuild')
        
        # Step 20: Re-scan fixed assets
        emit_progress(scan_id, STEP_RESCAN, 'running', 'Re-scanning fixed assets...')
        new_k8s_findings = []
        if os.path.exists(deployment_path):
            scan_result = scan_k8s_config(deployment_path)
            new_k8s_findings = summarize_findings(scan_result)
        
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
            'cspm': len(cspm_findings),
            'runtime': len(runtime_findings),
            'network': len(network_findings)
        }
        
        emit_progress(scan_id, STEP_METRICS, 'success', 'Scan complete!', metrics)
        log_activity('Security summary generated')
        
        # Mark as complete
        scan_results[scan_id]['status'] = 'complete'
        scan_results[scan_id]['metrics'] = metrics
        
    except Exception as e:
        emit_progress(scan_id, -1, 'error', f'Error: {str(e)}')
        scan_results[scan_id]['status'] = 'error'
        scan_results[scan_id]['error'] = str(e)


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


if __name__ == '__main__':
    import os
    port = int(os.getenv('PORT', 8000))
    socketio.run(app, debug=False, host='0.0.0.0', port=port)
