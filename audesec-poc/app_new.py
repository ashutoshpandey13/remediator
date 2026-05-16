from rich import print
import os
import shutil
import subprocess
import time

# Import configuration
from config import get_repo_config_from_input, find_files_in_repo

# Import Git operations
from agents.git_operations import (
    clone_repository,
    create_branch,
    commit_changes,
    push_branch,
    create_pull_request,
    generate_pr_body
)

# Import scanning agents
from agents.scanner import scan_k8s_config, summarize_findings
from agents.image_scanner import scan_image, summarize_cves
from agents.findings import combine_findings
from agents.jira_agent import create_jira_ticket
from agents.remediation import generate_remediation
from agents.validator import validate_yaml, validate_package_json


def main():
    """Main workflow for automated security remediation."""
    
    # Step 1: Get repository configuration
    print("\n[bold cyan]═══ STEP 1: Repository Configuration ═══[/bold cyan]\n")
    config = get_repo_config_from_input()
    print(f"✓ Repository: {config.repo_url}")
    
    # Step 2: Clone repository
    print("\n[bold cyan]═══ STEP 2: Cloning Repository ═══[/bold cyan]\n")
    repo_path = clone_repository(config.repo_url, "cloned_repo")
    print(f"✓ Cloned to: {repo_path}")
    
    # Step 3: Find required files
    print("\n[bold cyan]═══ STEP 3: Locating Files ═══[/bold cyan]\n")
    files = find_files_in_repo(repo_path, config)
    
    if not files["deployment_yaml"]:
        print("[yellow]⚠ Warning: deployment.yaml not found[/yellow]")
    else:
        print(f"✓ Deployment YAML: {files['deployment_yaml']}")
    
    if not files["package_json"]:
        print("[yellow]⚠ Warning: package.json not found[/yellow]")
    else:
        print(f"✓ Package JSON: {files['package_json']}")
    
    if not files["dockerfile"]:
        print("[yellow]⚠ Warning: Dockerfile not found[/yellow]")
    else:
        print(f"✓ Dockerfile: {files['dockerfile']}")
    
    # Step 4: Kubernetes Configuration Scan
    k8s_findings = []
    if files["deployment_yaml"]:
        print("\n[bold blue]═══ STEP 4: Kubernetes Security Scan ═══[/bold blue]\n")
        k8s_scan = scan_k8s_config(files["deployment_yaml"])
        k8s_findings = summarize_findings(k8s_scan)
        
        print(f"Found {len(k8s_findings)} Kubernetes misconfigurations:\n")
        for finding in k8s_findings[:5]:
            severity = finding.get("severity", "UNKNOWN")
            title = finding.get("title", "N/A")
            print(f"  [{severity}] {title}")
        
        if len(k8s_findings) > 5:
            print(f"  ... and {len(k8s_findings) - 5} more")
    
    # Step 5: Container Image CVE Scan
    cves = []
    image_name = None
    
    if files["dockerfile"]:
        print("\n[bold red]═══ STEP 5: Building and Scanning Container Image ═══[/bold red]\n")
        
        # Extract image name from dockerfile directory
        dockerfile_dir = os.path.dirname(files["dockerfile"])
        image_name = f"scan-{os.path.basename(repo_path)}"
        
        print(f"Building image: {image_name}")
        build_result = subprocess.run(
            ["docker", "build", "-t", image_name, dockerfile_dir],
            capture_output=True,
            text=True
        )
        
        if build_result.returncode == 0:
            print("✓ Image built successfully")
            
            print(f"Scanning image for CVEs...")
            image_scan = scan_image(image_name)
            cves = summarize_cves(image_scan)
            
            print(f"\nFound {len(cves)} CVEs:\n")
            for cve in cves[:5]:
                severity = cve.get("severity", "UNKNOWN")
                cve_id = cve.get("cve", "N/A")
                package = cve.get("package", "N/A")
                print(f"  [{severity}] {cve_id} in {package}")
            
            if len(cves) > 5:
                print(f"  ... and {len(cves) - 5} more")
        else:
            print(f"[yellow]⚠ Image build failed: {build_result.stderr}[/yellow]")
    
    # Step 6: Combine Findings
    print("\n[bold magenta]═══ STEP 6: Unified Security Findings ═══[/bold magenta]\n")
    combined = combine_findings(k8s_findings, cves)
    
    critical_high = [f for f in combined if f["severity"] in ["HIGH", "CRITICAL"]]
    print(f"Total findings: {len(combined)}")
    print(f"Critical/High severity: {len(critical_high)}")
    
    # Step 7: Create JIRA Tickets
    print("\n[bold yellow]═══ STEP 7: Creating JIRA Tickets ═══[/bold yellow]\n")
    
    jira_tickets = []
    for finding in critical_high[:5]:
        try:
            ticket = create_jira_ticket(finding)
            jira_tickets.append(ticket)
            print(f"✓ Created ticket: {ticket}")
        except Exception as e:
            print(f"[yellow]⚠ Failed to create ticket: {e}[/yellow]")
    
    # Step 8: AI-Powered Remediation
    print("\n[bold green]═══ STEP 8: AI-Powered Remediation ═══[/bold green]\n")
    
    if not files["deployment_yaml"] or not files["package_json"]:
        print("[red]✗ Cannot proceed: Required files not found[/red]")
        return
    
    with open(files["deployment_yaml"], "r") as f:
        deployment_yaml = f.read()
    
    with open(files["package_json"], "r") as f:
        package_json = f.read()
    
    print("Generating remediation with AI...")
    remediation = generate_remediation(combined, deployment_yaml, package_json)
    
    # Step 9: Apply Remediation
    print("\n[bold green]═══ STEP 9: Applying Remediation ═══[/bold green]\n")
    
    if "===FIXED_PACKAGE_JSON===" not in remediation:
        print("[red]✗ Invalid AI response format[/red]")
        return
    
    deployment_parts = remediation.split("===FIXED_PACKAGE_JSON===", 1)
    fixed_yaml = deployment_parts[0].replace("===FIXED_DEPLOYMENT===", "").strip()
    fixed_package_json = deployment_parts[1].strip()
    
    # Write fixed files back to repository
    with open(files["deployment_yaml"], "w") as f:
        f.write(fixed_yaml)
    print(f"✓ Updated: {files['deployment_yaml']}")
    
    with open(files["package_json"], "w") as f:
        f.write(fixed_package_json)
    print(f"✓ Updated: {files['package_json']}")
    
    # Step 10: Validate Fixed Files
    print("\n[bold green]═══ STEP 10: Validating Fixed Files ═══[/bold green]\n")
    
    yaml_valid = validate_yaml(files["deployment_yaml"])
    package_valid = validate_package_json(files["package_json"])
    
    print(f"YAML Valid: {'✓' if yaml_valid else '✗'}")
    print(f"Package JSON Valid: {'✓' if package_valid else '✗'}")
    
    if not yaml_valid or not package_valid:
        print("[red]✗ Validation failed, aborting[/red]")
        return
    
    # Step 11: Create Branch and Commit
    print("\n[bold cyan]═══ STEP 11: Creating Git Branch ═══[/bold cyan]\n")
    
    create_branch(repo_path, config.branch_name)
    print(f"✓ Created branch: {config.branch_name}")
    
    commit_message = f"""Security remediation: Fix {len(critical_high)} critical/high vulnerabilities

- Fixed {len(k8s_findings)} Kubernetes misconfigurations
- Resolved {len(cves)} CVEs
- Updated dependencies to secure versions
- Applied security best practices

Generated by AudeSec-POC
"""
    
    commit_changes(repo_path, commit_message)
    print("✓ Changes committed")
    
    # Step 12: Push and Create PR
    print("\n[bold cyan]═══ STEP 12: Creating Pull Request ═══[/bold cyan]\n")
    
    try:
        push_branch(repo_path, config.branch_name)
        print("✓ Branch pushed to remote")
        
        pr_body = generate_pr_body(
            len(cves),
            0,  # Will be updated after re-scan
            len(k8s_findings),
            0,  # Will be updated after re-scan
            critical_high
        )
        
        pr_url = create_pull_request(
            config.repo_url,
            config.branch_name,
            "🔒 Security Remediation: Fix Critical Vulnerabilities",
            pr_body
        )
        
        print(f"✓ Pull Request created: {pr_url}")
        
    except Exception as e:
        print(f"[yellow]⚠ PR creation failed: {e}[/yellow]")
        print("You can manually push and create PR from the branch")
    
    # Step 13: Rebuild Image
    print("\n[bold blue]═══ STEP 13: Rebuilding Container Image ═══[/bold blue]\n")
    
    if files["dockerfile"]:
        remediated_image = f"remediated-{os.path.basename(repo_path)}"
        
        build_result = subprocess.run(
            ["docker", "build", "-t", remediated_image, dockerfile_dir],
            capture_output=True,
            text=True
        )
        
        if build_result.returncode == 0:
            print(f"✓ Remediated image built: {remediated_image}")
        else:
            print(f"[yellow]⚠ Build failed: {build_result.stderr}[/yellow]")
    
    # Step 14: Re-scan Fixed Assets
    print("\n[bold blue]═══ STEP 14: Re-scanning Fixed Assets ═══[/bold blue]\n")
    
    # Re-scan Kubernetes config
    fixed_k8s_scan = scan_k8s_config(files["deployment_yaml"])
    fixed_k8s_findings = summarize_findings(fixed_k8s_scan)
    
    print(f"Fixed K8s findings: {len(fixed_k8s_findings)}")
    
    # Re-scan image
    fixed_cves = []
    if files["dockerfile"] and build_result.returncode == 0:
        fixed_image_scan = scan_image(remediated_image)
        fixed_cves = summarize_cves(fixed_image_scan)
        print(f"Fixed CVEs: {len(fixed_cves)}")
    
    # Step 15: Security Improvement Summary
    print("\n[bold green]═══ STEP 15: Security Improvement Summary ═══[/bold green]\n")
    
    print(f"{'Metric':<25} {'Before':<10} {'After':<10} {'Improvement':<15}")
    print("─" * 60)
    print(f"{'CVEs':<25} {len(cves):<10} {len(fixed_cves):<10} {len(cves) - len(fixed_cves):<15}")
    print(f"{'Misconfigurations':<25} {len(k8s_findings):<10} {len(fixed_k8s_findings):<10} {len(k8s_findings) - len(fixed_k8s_findings):<15}")
    
    improvement_pct = 0
    if len(combined) > 0:
        improvement_pct = ((len(combined) - len(fixed_k8s_findings) - len(fixed_cves)) / len(combined)) * 100
    
    print(f"\n✓ Overall improvement: {improvement_pct:.1f}%")
    
    # Step 16: Runtime Validation
    if files["dockerfile"] and build_result.returncode == 0:
        print("\n[bold blue]═══ STEP 16: Runtime Validation ═══[/bold blue]\n")
        
        print("Starting container for health check...")
        container = subprocess.Popen(
            ["docker", "run", "--rm", "-p", "3000:3000", remediated_image],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        time.sleep(5)
        
        health = subprocess.run(
            ["curl", "-s", "http://localhost:3000/health"],
            capture_output=True,
            text=True
        )
        
        if health.returncode == 0:
            print(f"✓ Health check passed: {health.stdout}")
        else:
            print("[yellow]⚠ Health check failed[/yellow]")
        
        container.kill()
    
    print("\n[bold green]═══ REMEDIATION COMPLETE ═══[/bold green]\n")
    print(f"Repository: {config.repo_url}")
    print(f"Branch: {config.branch_name}")
    print(f"Cloned to: {repo_path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[yellow]Operation cancelled by user[/yellow]")
    except Exception as e:
        print(f"\n[red]✗ Error: {e}[/red]")
        import traceback
        traceback.print_exc()