import subprocess
import json


def scan_image(image_name: str):

    output_file = "reports/image_scan.json"

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
        text=True
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
