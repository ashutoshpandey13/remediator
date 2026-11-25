from rich import print
from agents.logger import log_activity

from agents.sast_scanner import (
    scan_code,
    summarize_sast
)

from agents.secret_scanner import (
    scan_secrets,
    summarize_secrets
)

from agents.cspm_scanner import (
    scan_cspm,
    summarize_cspm
)

from agents.dependency_validator import (
    validate_npm_package
)

from agents.runtime_scanner import (
    scan_runtime,
    summarize_runtime
)

from agents.network_scanner import (
    scan_network,
    summarize_network
)

########## Scan kubernetes files

from agents.scanner import (
    scan_k8s_config,
    summarize_findings
)

from agents.image_scanner import (
    scan_image,
    summarize_cves
)

yaml_path = "vulnerable-app/deployment.yaml"

print("\n[bold blue]=== Kubernetes Scan ===[/bold blue]\n")

k8s_scan = scan_k8s_config(
    yaml_path
)

k8s_findings = summarize_findings(
    k8s_scan
)

log_activity(
    "Kubernetes scan completed"
)

for finding in k8s_findings:
    print(finding)

########## CVE scans

print("\n[bold red]=== CVE Scan ===[/bold red]\n")

image_scan = scan_image(
    "vulnerable-node-app"
)

cves = summarize_cves(
    image_scan
)

log_activity(
    "Container CVE scan completed"
)

for cve in cves[:10]:
    print(cve)

####### SAST Scan

print(
    "\n[bold cyan]=== SAST Scan ===[/bold cyan]\n"
)

sast_scan = scan_code(
    "vulnerable-app/"
)

sast_findings = summarize_sast(
    sast_scan
)

for finding in sast_findings:

    print(finding)

log_activity(
    "SAST scan completed"
)

######### SECRET SCAN

print(
    "\n[bold yellow]=== SECRET SCAN ===[/bold yellow]\n"
)

secret_scan = scan_secrets(
    "vulnerable-app/"
)

secret_findings = summarize_secrets(
    secret_scan
)

for finding in secret_findings:

    print(finding)

log_activity(
    "Secret scan completed"
)

######### CSPM SCAN

print(
    "\n[bold blue]=== CSPM Scan ===[/bold blue]\n"
)

cspm_scan = scan_cspm()

cspm_findings = summarize_cspm(
    cspm_scan
)

for finding in cspm_findings:

    print(finding)

log_activity(
    "CSPM scan completed"
)

########## Runtime Scan

print(
    "\n[bold red]=== RUNTIME SECURITY ===[/bold red]\n"
)

runtime_scan = scan_runtime()

runtime_findings = summarize_runtime(
    runtime_scan
)

for finding in runtime_findings:

    print(finding)

log_activity(
    "Runtime scan completed"
)


########## Network Scan

print(
    "\n[bold cyan]=== NETWORK EXPOSURE ===[/bold cyan]\n"
)

network_scan = scan_network()

network_findings = summarize_network(
    network_scan
)

for finding in network_findings:

    print(finding)

log_activity(
    "Network exposure scan completed"
)

########## Combine findings

from agents.findings import combine_findings

combined = combine_findings(
    k8s_findings,
    cves,
    sast_findings,
    secret_findings,
    cspm_findings,
    runtime_findings,
    network_findings
)

log_activity(
    "Unified findings generated"
)

print("\n[bold magenta]=== Unified Findings ===[/bold magenta]\n")

for finding in combined:
    print(finding)

######## Create JIRA

from agents.jira_agent import (
    create_jira_ticket
)

print(
    "\n[bold yellow]=== Creating JIRA Tickets ===[/bold yellow]\n"
)

important_findings = [
    finding for finding in combined
    if finding["severity"] in [
        "HIGH",
        "CRITICAL"
    ]
]

jira_tickets = []

for finding in important_findings[:5]:

    try:

        ticket = create_jira_ticket(
            finding
        )

        jira_tickets.append(ticket)

        log_activity(
           f"Created JIRA ticket {ticket}"
        )

        print(
            f"Created Ticket: {ticket}"
        )

    except Exception as e:

        print(
            f"Failed creating ticket: {e}"
        )

########### Remediation

from agents.remediation import (
    generate_remediation
)

with open(
    "vulnerable-app/deployment.yaml",
    "r"
) as f:
    deployment_yaml = f.read()

with open(
    "vulnerable-app/package.json",
    "r"
) as f:
    package_json = f.read()

remediation = generate_remediation(
    combined,
    deployment_yaml,
    package_json
)

log_activity(
    "AI remediation generated"
)

print(
    "\n[bold green]=== AI REMEDIATION ===[/bold green]\n"
)

print(remediation)

######### save fixed files

import os

os.makedirs("fixed", exist_ok=True)

if "===FIXED_PACKAGE_JSON===" not in remediation:
    raise Exception(
        "LLM response format invalid"
    )

'''
deployment_parts = remediation.split(
    "===FIXED_PACKAGE_JSON===",
    1
)

#fixed_yaml = deployment_parts[0].replace(
#    "===FIXED_DEPLOYMENT===",
#    ""
#).strip()

fixed_yaml = (
    deployment_split[0]
    .replace(
        "===FIXED_DEPLOYMENT===",
        ""
    )
    .replace("```yaml", "")
    .replace("```", "")
    .strip()
)

fixed_package_json = deployment_parts[1].strip()
'''

if "===FIXED_SOURCE_CODE===" not in remediation:

    raise Exception(
        "LLM response missing source code section"
    )

deployment_split = remediation.split(
    "===FIXED_PACKAGE_JSON===",
    1
)

fixed_yaml = (
    deployment_split[0]
    .replace(
        "===FIXED_DEPLOYMENT===",
        ""
    )
    .replace("```yaml", "")
    .replace("```", "")
    .strip()
)

remaining = deployment_split[1]

package_split = remaining.split(
    "===FIXED_SOURCE_CODE===",
    1
)

#fixed_package_json = package_split[0].strip()

fixed_package_json = (
    package_split[0]
    .replace("```json", "")
    .replace("```", "")
    .strip()
)

#fixed_source_code = package_split[1].strip()

fixed_source_code = (
    package_split[1]
    .replace("```python", "")
    .replace("```", "")
    .strip()
)

with open(
    "fixed/deployment.yaml",
    "w"
) as f:
    f.write(fixed_yaml)

with open(
    "fixed/package.json",
    "w"
) as f:
    f.write(fixed_package_json)

with open(
    "fixed/vulnerable_code.py",
    "w"
) as f:

    f.write(
        fixed_source_code
    )

####### validate generated files

from agents.validator import (
    validate_yaml,
    validate_package_json
)

print("\n=== VALIDATION ===\n")

yaml_valid = validate_yaml(
    "fixed/deployment.yaml"
)

package_valid = validate_package_json(
    "fixed/package.json"
)

log_activity(
    "Validation completed"
)

print("YAML Valid:", yaml_valid)
print("Package JSON Valid:", package_valid)

import json

print("\n=== DEPENDENCY VALIDATION ===\n")

with open(
    "fixed/package.json",
    "r"
) as f:

    pkg = json.load(f)

dependencies = pkg.get(
    "dependencies",
    {}
)

for package, version in dependencies.items():

    valid = validate_npm_package(
        package,
        version
    )

    print(
        f"{package}@{version} : {valid}"
    )

    if not valid:

        raise Exception(
            f"Invalid dependency version: "
            f"{package}@{version}"
        )

############ Rebuild Image

import shutil
import subprocess

shutil.copy(
    "vulnerable-app/package.json",
    "vulnerable-app/package.json.bak"
)

shutil.copy(
    "fixed/package.json",
    "vulnerable-app/package.json"
)

shutil.copy(
    "vulnerable-app/vulnerable_code.py",
    "vulnerable-app/vulnerable_code.py.bak"
)

shutil.copy(
    "fixed/vulnerable_code.py",
    "vulnerable-app/vulnerable_code.py"
)

print("\n=== REBUILDING IMAGE ===\n")

build_result = subprocess.run(
    [
        "docker",
        "build",
        "-t",
        "remediated-node-app",
        "./vulnerable-app"
    ],
    capture_output=True,
    text=True
)

if build_result.returncode != 0:

    print(build_result.stderr)

    raise Exception(
        "Docker build failed"
    )

log_activity(
    "Docker image rebuilt"
)

########## Re-scan fixed image

fixed_image_scan = scan_image(
    "remediated-node-app"
)

fixed_cves = summarize_cves(
    fixed_image_scan
)

print("\n=== FIXED CVEs ===\n")

for cve in fixed_cves[:10]:
    print(cve)

######## Re-scan fixed yaml

fixed_k8s_scan = scan_k8s_config(
    "fixed/deployment.yaml"
)

fixed_k8s_findings = summarize_findings(
    fixed_k8s_scan
)

print("\n=== FIXED K8s FINDINGS ===\n")

for finding in fixed_k8s_findings:
    print(finding)

########### Compare Results

print("\n=== SECURITY IMPROVEMENT ===\n")

print(
    f"Original CVEs: {len(cves)}"
)

print(
    f"Fixed CVEs: {len(fixed_cves)}"
)

print(
    f"Original Misconfigs: {len(k8s_findings)}"
)

print(
    f"Fixed Misconfigs: {len(fixed_k8s_findings)}"
)

shutil.copy(
    "vulnerable-app/package.json.bak",
    "vulnerable-app/package.json"
)

shutil.copy(
    "vulnerable-app/vulnerable_code.py.bak",
    "vulnerable-app/vulnerable_code.py"
)

################# Runtime validation

print("\n=== RUNTIME VALIDATION ===\n")

container = subprocess.Popen([
    "docker",
    "run",
    "--rm",
    "-p",
    "3005:3000",
    "remediated-node-app"
])

import time
time.sleep(5)

health = subprocess.run(
    [
        "curl",
        "http://localhost:3005/health"
    ],
    capture_output=True,
    text=True
)

print(
    "Health Check:",
    health.stdout
)

container.kill()

log_activity(
    "Runtime health validation passed"
)

import json

summary = {

    "original_cves": len(cves),

    "fixed_cves": len(fixed_cves),

    "original_misconfigs": len(
        k8s_findings
    ),

    "fixed_misconfigs": len(
        fixed_k8s_findings
    ),

    "jira_tickets": jira_tickets,

    "deployment_health": "HEALTHY"
}

with open(
    "reports/findings_summary.json",
    "w"
) as f:

    json.dump(
        summary,
        f,
        indent=2
    )

log_activity(
    "Security summary generated"
)


