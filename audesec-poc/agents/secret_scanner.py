import subprocess
import json


def scan_secrets(path):

    output_file = "reports/secret_scan.json"

    cmd = [
        "gitleaks",
        "dir",
        path,
        "--report-format",
        "json",
        "--report-path",
        output_file
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )

    # Gitleaks returns:
    # 0 = no findings
    # 1 = leaks found

    if result.returncode not in [0, 1]:

        print(result.stderr)

        raise Exception(
            "Secret scan failed"
        )

    with open(output_file, "r") as f:

        return json.load(f)


def summarize_secrets(scan_result):

    findings = []

    for result in scan_result:

        findings.append({

            "type": "SECRET",

            "severity": "CRITICAL",

            "rule": result.get(
                "RuleID"
            ),

            "description": result.get(
                "Description"
            ),

            "file": result.get(
                "File"
            ),

            "secret": result.get(
                "Secret"
            )
        })

    return findings
