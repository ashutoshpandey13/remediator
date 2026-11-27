import json
import os
import subprocess
import tempfile

from remediator.scanners.feed_loader import load_feed

CSPM_TIMEOUT_SECONDS = 600

# Directories that never hold the repository's own infrastructure code
SKIP_DIRS = "node_modules,.git,vendor"

# Trivy result types that already have their own scan step (Kubernetes manifests
# and Dockerfiles); everything else is infrastructure-as-code: Terraform,
# CloudFormation, Helm, Azure ARM, ...
COVERED_BY_OTHER_SCANS = {"kubernetes", "dockerfile"}


def scan_cspm(path):
    """
    Cloud security posture of the repository: scan its infrastructure-as-code
    (Terraform, CloudFormation, Helm, ...) for cloud misconfigurations.
    """

    # A private report file per call, so concurrent scans never read each other's results
    with tempfile.TemporaryDirectory(prefix="audesec-cspm-") as report_dir:

        output_file = os.path.join(report_dir, "cspm_scan.json")

        cmd = [
            "trivy",
            "config",
            "--format",
            "json",
            "--skip-dirs",
            SKIP_DIRS,
            "-o",
            output_file,
            path
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=CSPM_TIMEOUT_SECONDS
        )

        if result.returncode != 0:
            raise Exception(result.stderr)

        with open(output_file, "r") as f:
            return json.load(f)


def summarize_cspm(scan_result):

    findings = []

    for result in scan_result.get("Results") or []:

        if (result.get("Type") or "").lower() in COVERED_BY_OTHER_SCANS:
            continue

        for misconfig in result.get("Misconfigurations") or []:

            cause = misconfig.get("CauseMetadata") or {}

            findings.append({
                "id": misconfig.get("ID"),
                "title": misconfig.get("Title"),
                "severity": misconfig.get("Severity"),
                "message": misconfig.get("Message"),
                "file": result.get("Target"),
                "resource": cause.get("Resource")
            })

    return findings


def scan_cspm_feed():
    """Cloud posture findings exported by another tool (e.g. Prowler) to CSPM_FINDINGS_PATH."""
    return load_feed("CSPM_FINDINGS_PATH")


def summarize_cspm_feed(scan_result):

    findings = []

    for result in scan_result:

        findings.append({
            "id": result.get("CheckID"),
            "severity": result.get("Severity"),
            "message": result.get("Description"),
            "resource": result.get("Resource")
        })

    return findings
