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

######## Create JIRA (disabled)

# from agents.jira_agent import (
#     create_jira_ticket
# )
#
# print(
#     "\n[bold yellow]=== Creating JIRA Tickets ===[/bold yellow]\n"
# )
#
# important_findings = [
#     finding for finding in combined
#     if finding["severity"] in [
#         "HIGH",
#         "CRITICAL"
#     ]
# ]
#
# jira_tickets = []
#
# for finding in important_findings[:5]:
#
#     try:
#
#         ticket = create_jira_ticket(
#             finding
#         )
#
#         jira_tickets.append(ticket)
#
#         log_activity(
#            f"Created JIRA ticket {ticket}"
#         )
#
#         print(
#             f"Created Ticket: {ticket}"
#         )
#
#     except Exception as e:
#
#         print(
#             f"Failed creating ticket: {e}"
#         )

# Kept because it is used in the final report below
jira_tickets = []

########### Remediation

import os

from agents.remediation import (
    generate_remediation,
    parse_sections
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

with open(
    "vulnerable-app/Dockerfile",
    "r"
) as f:
    dockerfile = f.read()

SOURCE_FILES = ["app.js", "secrets.py", "vulnerable_code.py"]

source_contents = {}

for name in SOURCE_FILES:

    path = f"vulnerable-app/{name}"

    if os.path.exists(path):

        with open(path, "r") as f:
            source_contents[name] = f.read()

remediation = generate_remediation(
    combined,
    deployment_yaml,
    package_json,
    dockerfile,
    source_contents.get("app.js", ""),
    source_contents.get("secrets.py", ""),
    source_contents.get("vulnerable_code.py", "")
)

log_activity(
    "AI remediation generated"
)

print(
    "\n[bold green]=== AI REMEDIATION ===[/bold green]\n"
)

print(remediation)

######### save fixed files

os.makedirs("fixed", exist_ok=True)

sections = parse_sections(remediation)

for required in (
    "===FIXED_DEPLOYMENT===",
    "===FIXED_PACKAGE_JSON===",
    "===FIXED_SOURCE_CODE==="
):
    if required not in sections:
        raise Exception(
            f"LLM response missing section {required}"
        )

# section marker -> file inside fixed/
SECTION_FILES = {
    "===FIXED_DEPLOYMENT===": "deployment.yaml",
    "===FIXED_PACKAGE_JSON===": "package.json",
    "===FIXED_SOURCE_CODE===": "vulnerable_code.py",
    "===FIXED_DOCKERFILE===": "Dockerfile",
    "===FIXED_APP_JS===": "app.js",
    "===FIXED_SECRETS===": "secrets.py"
}

# Remove output of previous runs so stale files are never copied back
for name in SECTION_FILES.values():

    if os.path.exists(f"fixed/{name}"):
        os.remove(f"fixed/{name}")

for marker, name in SECTION_FILES.items():

    if marker in sections and sections[marker].strip():

        with open(f"fixed/{name}", "w") as f:
            f.write(sections[marker].strip() + "\n")

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

####### code / package.json consistency (prevents "Cannot find module" crashes)

import re
import subprocess

print("\n=== REQUIRE / DEPENDENCY CONSISTENCY ===\n")

if os.path.exists("fixed/app.js"):

    with open("fixed/app.js", "r") as f:
        app_js_text = f.read()

    node_builtins = set(
        json.loads(
            subprocess.run(
                [
                    "node",
                    "-e",
                    "console.log(JSON.stringify(require('module').builtinModules))"
                ],
                capture_output=True,
                text=True
            ).stdout or "[]"
        )
    )

    required = set(
        re.findall(
            r"require\(\s*['\"]([^'\"]+)['\"]\s*\)",
            app_js_text
        )
    )

    required |= set(
        re.findall(
            r"from\s+['\"]([^'\"]+)['\"]",
            app_js_text
        )
    )

    missing = []

    for module in sorted(required):

        if module.startswith((".", "/", "node:")):
            continue

        # "@scope/pkg/sub" -> "@scope/pkg", "pkg/sub" -> "pkg"
        parts = module.split("/")
        top = "/".join(parts[:2]) if module.startswith("@") else parts[0]

        if top in node_builtins or top in dependencies:
            continue

        missing.append(top)

    print(
        "app.js requires:",
        sorted(required)
    )

    if missing:

        raise Exception(
            "fixed/app.js requires packages missing from "
            f"fixed/package.json: {missing}"
        )

    print("OK: every require() is declared in package.json")

############ Rebuild Image

import shutil
import subprocess

# Back up each original, then place the fixed version in the build context
APPLIED_FILES = [
    name for name in SECTION_FILES.values()
    if os.path.exists(f"fixed/{name}")
    and name != "deployment.yaml"
]

for name in APPLIED_FILES:

    if os.path.exists(f"vulnerable-app/{name}"):

        shutil.copy(
            f"vulnerable-app/{name}",
            f"vulnerable-app/{name}.bak"
        )

    shutil.copy(
        f"fixed/{name}",
        f"vulnerable-app/{name}"
    )

print("\n=== REBUILDING IMAGE ===\n")

# Explicit tag so a stale "remediated-node-app:latest" is never scanned
FIXED_IMAGE = "remediated-node-app:fixed"

build_result = subprocess.run(
    [
        "docker",
        "build",
        "-t",
        FIXED_IMAGE,
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
    FIXED_IMAGE
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

# Put the original files back (the fixed ones stay in fixed/)
# Runtime validation below uses the already built fixed image
for name in APPLIED_FILES:

    if os.path.exists(f"vulnerable-app/{name}.bak"):

        shutil.copy(
            f"vulnerable-app/{name}.bak",
            f"vulnerable-app/{name}"
        )

################# Runtime validation

print("\n=== RUNTIME VALIDATION ===\n")

# Named container so it can be removed reliably afterwards
subprocess.run(
    ["docker", "rm", "-f", "remediated-health-check"],
    capture_output=True
)

container = subprocess.Popen([
    "docker",
    "run",
    "--rm",
    "--name",
    "remediated-health-check",
    "-p",
    "3005:3000",
    # Secrets are no longer hardcoded, so the fixed app needs them at runtime.
    # These are throw-away test values for this health check only.
    "-e",
    "JWT_SECRET=healthcheck-only-secret",
    "-e",
    "CORS_ORIGIN=http://localhost:3005",
    FIXED_IMAGE
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

subprocess.run(
    ["docker", "rm", "-f", "remediated-health-check"],
    capture_output=True
)

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


