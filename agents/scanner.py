import subprocess
import json

def scan_k8s_config(file_path: str):

    output_file = "reports/k8s_scan.json"

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
        text=True
    )

    if result.returncode != 0:
        raise Exception(result.stderr)

    with open(output_file, "r") as f:
        return json.load(f)

def summarize_findings(scan_result):

    findings = []

    for result in scan_result.get("Results", []):

        for misconfig in result.get(
            "Misconfigurations",
            []
        ):

            findings.append({
                "id": misconfig.get("ID"),
                "title": misconfig.get("Title"),
                "severity": misconfig.get("Severity"),
                "message": misconfig.get("Message")
            })

    return findings
