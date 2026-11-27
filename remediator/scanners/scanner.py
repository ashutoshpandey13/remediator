import json
import os
import subprocess
import tempfile

TRIVY_CONFIG_TIMEOUT_SECONDS = 300


def scan_k8s_config(file_path: str):

    # A private report file per call, so concurrent scans never read each other's results
    with tempfile.TemporaryDirectory(prefix="audesec-k8s-") as report_dir:

        output_file = os.path.join(report_dir, "k8s_scan.json")

        cmd = [
            "trivy",
            "config",
            "--format",
            "json",
            "-o",
            output_file,
            file_path
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TRIVY_CONFIG_TIMEOUT_SECONDS
        )

        if result.returncode != 0:
            raise Exception(result.stderr)

        with open(output_file, "r") as f:
            return json.load(f)


def summarize_findings(scan_result):

    findings = []

    for result in scan_result.get("Results") or []:

        for misconfig in result.get("Misconfigurations") or []:

            findings.append({
                "id": misconfig.get("ID"),
                "title": misconfig.get("Title"),
                "severity": misconfig.get("Severity"),
                "message": misconfig.get("Message")
            })

    return findings
