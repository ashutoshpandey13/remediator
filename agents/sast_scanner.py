import json
import os
import subprocess

SEMGREP_TIMEOUT_SECONDS = 600

# Semgrep reports ERROR / WARNING / INFO - map to the severities used everywhere else
SEMGREP_SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW"
}


def scan_code(path):

    os.makedirs("reports", exist_ok=True)

    output_file = "reports/sast_scan.json"

    # Never read a stale report from a previous run
    if os.path.exists(output_file):
        os.remove(output_file)

    cmd = [
        "semgrep",
        "scan",
        "--config",
        "auto",
        "--json",
        "--output",
        output_file,
        path
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=SEMGREP_TIMEOUT_SECONDS
    )

    # semgrep returns:
    # 0 = no findings
    # 1 = findings found

    if result.returncode not in [0, 1]:

        raise Exception(
            f"Semgrep scan failed: {result.stderr}"
        )

    with open(output_file, "r") as f:
        return json.load(f)


def summarize_sast(scan_result):

    findings = []

    for result in scan_result.get(
        "results",
        []
    ):

        extra = result.get(
            "extra",
            {}
        )

        raw_severity = extra.get(
            "severity"
        )

        findings.append({

            "type": "SAST",

            "id": result.get(
                "check_id"
            ),

            "severity": SEMGREP_SEVERITY_MAP.get(
                raw_severity,
                raw_severity
            ),

            "message": extra.get(
                "message"
            ),

            "file": result.get(
                "path"
            )
        })

    return findings
