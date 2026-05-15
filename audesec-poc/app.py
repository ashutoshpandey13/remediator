from rich import print

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

for cve in cves[:10]:
    print(cve)

########## Combine findings

from agents.findings import combine_findings

combined = combine_findings(
    k8s_findings,
    cves
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

deployment_parts = remediation.split(
    "===FIXED_PACKAGE_JSON===",
    1
)

fixed_yaml = deployment_parts[0].replace(
    "===FIXED_DEPLOYMENT===",
    ""
).strip()

fixed_package_json = deployment_parts[1].strip()

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

print("YAML Valid:", yaml_valid)
print("Package JSON Valid:", package_valid)

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

################# Runtime validation

print("\n=== RUNTIME VALIDATION ===\n")

container = subprocess.Popen([
    "docker",
    "run",
    "--rm",
    "-p",
    "3000:3000",
    "remediated-node-app"
])

import time
time.sleep(5)

health = subprocess.run(
    [
        "curl",
        "http://localhost:3000/health"
    ],
    capture_output=True,
    text=True
)

print(
    "Health Check:",
    health.stdout
)

container.kill()
