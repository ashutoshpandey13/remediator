from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import threading
import sys
import os
import subprocess
from datetime import datetime
import json

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import get_repository_config
from agents.git_operations import clone_repository, cleanup_cloned_repo
from agents.scanner import scan_k8s_config, summarize_findings
from agents.image_scanner import scan_image, summarize_cves
from agents.findings import combine_findings
from agents.jira_agent import create_jira_ticket
from agents.remediation import generate_remediation
from agents.validator import validate_yaml, validate_package_json
from agents.dockerfile_remediation import generate_dockerfile_remediation

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app, cors_allowed_origins="*")

# Store scan results
scan_results = {}

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


def run_security_scan(repo_url, scan_id):
    """Run the security scan workflow with progress updates."""
    try:
        emit_progress(scan_id, 0, 'running', f'Starting security scan for {repo_url}')
        
        # Step 0: Cleanup
        emit_progress(scan_id, 0, 'running', 'Cleaning up previous clones...')
        cleanup_cloned_repo()
        emit_progress(scan_id, 0, 'success', 'Cleanup complete')
        
        # Step 1: Get repository configuration
        emit_progress(scan_id, 1, 'running', 'Getting repository configuration...')
        config = get_repository_config(repo_url)
        emit_progress(scan_id, 1, 'success', f'Configuration loaded: {config["repo_name"]}', {
            'repo_name': config['repo_name'],
            'branch': config['branch']
        })
        
        # Step 2: Clone repository
        emit_progress(scan_id, 2, 'running', f'Cloning repository: {repo_url}')
        clone_dir = clone_repository(repo_url, config['branch'])
        emit_progress(scan_id, 2, 'success', f'Repository cloned to: {clone_dir}')
        
        # Step 3: Find files
        emit_progress(scan_id, 3, 'running', 'Discovering files...')
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
        
        emit_progress(scan_id, 3, 'success', f'Found {len(files_found)} files', {
            'files': files_found
        })
        
        # Step 4: Scan Kubernetes configs
        emit_progress(scan_id, 4, 'running', 'Scanning Kubernetes configurations...')
        k8s_findings = []
        if os.path.exists(deployment_path):
            scan_result = scan_k8s_config(deployment_path)
            k8s_findings = summarize_findings(scan_result)
            emit_progress(scan_id, 4, 'success', f'Found {len(k8s_findings)} Kubernetes issues', {
                'count': len(k8s_findings)
            })
        else:
            emit_progress(scan_id, 4, 'info', 'No Kubernetes files to scan')
        
        # Step 5: Build and scan container image
        emit_progress(scan_id, 5, 'running', 'Building and scanning container image...')
        cve_findings = []
        if os.path.exists(dockerfile_path):
            # Build image first
            build_cmd = ["docker", "build", "-t", config['image_name'], clone_dir]
            subprocess.run(build_cmd, capture_output=True)
            
            # Scan image
            scan_result = scan_image(config['image_name'])
            cve_findings = summarize_cves(scan_result)
            emit_progress(scan_id, 5, 'success', f'Found {len(cve_findings)} CVEs in container image', {
                'cve_count': len(cve_findings),
                'total_findings': len(cve_findings)
            })
        else:
            emit_progress(scan_id, 5, 'info', 'No Dockerfile to scan')
        
        # Step 6: Combine findings
        emit_progress(scan_id, 6, 'running', 'Combining security findings...')
        all_findings = combine_findings(k8s_findings, cve_findings)
        total_issues = len(all_findings)
        emit_progress(scan_id, 6, 'success', f'Total issues found: {total_issues}', {
            'total': total_issues,
            'k8s': len(k8s_findings),
            'cve': len(cve_findings)
        })
        
        # Step 7: Create JIRA tickets
        emit_progress(scan_id, 7, 'running', 'Creating JIRA tickets...')
        jira_keys = []
        try:
            for finding in all_findings[:5]:  # Limit to first 5
                key = create_jira_ticket(finding)
                jira_keys.append(key)
            emit_progress(scan_id, 7, 'success', f'Created {len(jira_keys)} JIRA tickets', {
                'tickets': jira_keys
            })
        except Exception as e:
            emit_progress(scan_id, 7, 'info', f'JIRA integration not configured: {str(e)}')
        
        # Step 8: Generate remediation
        emit_progress(scan_id, 8, 'running', 'Generating AI-powered remediation...')
        
        deployment_yaml = None
        package_json = None
        
        if os.path.exists(deployment_path):
            with open(deployment_path, 'r') as f:
                deployment_yaml = f.read()
        
        if os.path.exists(package_json_path):
            with open(package_json_path, 'r') as f:
                package_json = f.read()
        
        remediation = generate_remediation(
            json.dumps(all_findings, indent=2),
            deployment_yaml,
            package_json
        )
        emit_progress(scan_id, 8, 'success', 'Remediation generated')
        
        # Step 9: Apply fixes
        emit_progress(scan_id, 9, 'running', 'Applying security fixes...')
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
        
        emit_progress(scan_id, 9, 'success', f'Updated {len(files_updated)} files', {
            'files': files_updated
        })
        
        # Step 10: Validate fixes
        emit_progress(scan_id, 10, 'running', 'Validating fixed files...')
        validation_results = {}
        
        if 'deployment.yaml' in files_updated:
            yaml_valid = validate_yaml(deployment_path)
            validation_results['yaml'] = {'valid': yaml_valid, 'error': None if yaml_valid else 'Validation failed'}
        
        if 'package.json' in files_updated:
            json_valid = validate_package_json(package_json_path)
            validation_results['json'] = {'valid': json_valid, 'error': None if json_valid else 'Validation failed'}
        
        all_valid = all(v['valid'] for v in validation_results.values())
        
        if all_valid:
            emit_progress(scan_id, 10, 'success', 'All files validated successfully', validation_results)
        else:
            emit_progress(scan_id, 10, 'error', 'Validation failed', validation_results)
            scan_results[scan_id]['status'] = 'error'
            return
        
        # Step 11: Dockerfile remediation
        emit_progress(scan_id, 11, 'running', 'Updating Dockerfile for CVE fixes...')
        if os.path.exists(dockerfile_path):
            with open(dockerfile_path, 'r') as f:
                original_dockerfile = f.read()
            
            if cve_findings:
                fixed_dockerfile = generate_dockerfile_remediation(
                    original_dockerfile,
                    cve_findings[:10]
                )
                
                with open(dockerfile_path, 'w') as f:
                    f.write(fixed_dockerfile)
                
                emit_progress(scan_id, 11, 'success', 'Dockerfile updated')
            else:
                emit_progress(scan_id, 11, 'info', 'No CVEs to fix in Dockerfile')
        else:
            emit_progress(scan_id, 11, 'info', 'No Dockerfile found')
        
        # Step 12: Rebuild container
        emit_progress(scan_id, 12, 'running', 'Rebuilding container image...')
        new_cve_findings = []
        if os.path.exists(dockerfile_path):
            # Build image
            build_cmd = ["docker", "build", "-t", f"{config['image_name']}-fixed", clone_dir]
            subprocess.run(build_cmd, capture_output=True)
            
            # Scan new image
            scan_result = scan_image(f"{config['image_name']}-fixed")
            new_cve_findings = summarize_cves(scan_result)
            emit_progress(scan_id, 12, 'success', f'Rebuild complete. New CVE count: {len(new_cve_findings)}', {
                'new_cve_count': len(new_cve_findings)
            })
        else:
            emit_progress(scan_id, 12, 'info', 'No Dockerfile to rebuild')
        
        # Step 13: Re-scan fixed assets
        emit_progress(scan_id, 13, 'running', 'Re-scanning fixed assets...')
        new_k8s_findings = []
        if os.path.exists(deployment_path):
            scan_result = scan_k8s_config(deployment_path)
            new_k8s_findings = summarize_findings(scan_result)
        
        emit_progress(scan_id, 13, 'success', 'Re-scan complete', {
            'new_k8s_count': len(new_k8s_findings),
            'new_cve_count': len(new_cve_findings)
        })
        
        # Step 14: Calculate metrics
        emit_progress(scan_id, 14, 'running', 'Calculating improvement metrics...')
        
        old_k8s_count = len(k8s_findings)
        new_k8s_count = len(new_k8s_findings)
        k8s_fixed = old_k8s_count - new_k8s_count
        k8s_improvement = (k8s_fixed / old_k8s_count * 100) if old_k8s_count > 0 else 0
        
        old_cve_count = len(cve_findings)
        new_cve_count = len(new_cve_findings)
        cve_fixed = old_cve_count - new_cve_count
        cve_improvement = (cve_fixed / old_cve_count * 100) if old_cve_count > 0 else 0
        
        total_old = old_k8s_count + old_cve_count
        total_new = new_k8s_count + new_cve_count
        total_fixed = total_old - total_new
        total_improvement = (total_fixed / total_old * 100) if total_old > 0 else 0
        
        metrics = {
            'kubernetes': {
                'before': old_k8s_count,
                'after': new_k8s_count,
                'fixed': k8s_fixed,
                'improvement': round(k8s_improvement, 1)
            },
            'cve': {
                'before': old_cve_count,
                'after': new_cve_count,
                'fixed': cve_fixed,
                'improvement': round(cve_improvement, 1)
            },
            'total': {
                'before': total_old,
                'after': total_new,
                'fixed': total_fixed,
                'improvement': round(total_improvement, 1)
            }
        }
        
        emit_progress(scan_id, 14, 'success', 'Scan complete!', metrics)
        
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
    return render_template('index.html')


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
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)

# Made with Bob
