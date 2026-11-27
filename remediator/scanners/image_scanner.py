import os
import subprocess
import json
import tempfile

TRIVY_IMAGE_TIMEOUT_SECONDS = 900


def scan_image(image_name: str):

    # A private report file per call, so concurrent scans never read each other's results
    with tempfile.TemporaryDirectory(prefix="audesec-image-") as report_dir:

        output_file = os.path.join(report_dir, "image_scan.json")

        cmd = [
            "trivy",
            "image",
            "--format",
            "json",
            "-o",
            output_file,
            image_name
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TRIVY_IMAGE_TIMEOUT_SECONDS
        )

        if result.returncode != 0:
            raise Exception(result.stderr)

        with open(output_file, "r") as f:
            return json.load(f)


def summarize_cves(scan_result):

    findings = []

    for result in scan_result.get(
        "Results",
        []
    ):

        vulnerabilities = result.get(
            "Vulnerabilities",
            []
        )

        for vuln in vulnerabilities:

            findings.append({
                "cve": vuln.get(
                    "VulnerabilityID"
                ),
                "package": vuln.get(
                    "PkgName"
                ),
                "installed": vuln.get(
                    "InstalledVersion"
                ),
                "fixed": vuln.get(
                    "FixedVersion"
                ),
                "severity": vuln.get(
                    "Severity"
                )
            })

    return findings
