import json
import os
import subprocess

GITLEAKS_TIMEOUT_SECONDS = 300


def scan_secrets(path):

    os.makedirs("reports", exist_ok=True)

    output_file = "reports/secret_scan.json"

    # Never read a stale report from a previous run
    if os.path.exists(output_file):
        os.remove(output_file)

    cmd = [
        "gitleaks",
        "dir",
        path,
        "--no-banner",
        # Keep the secret values out of the report file, logs and UI
        "--redact",
        "--report-format",
        "json",
        "--report-path",
        output_file
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=GITLEAKS_TIMEOUT_SECONDS
    )

    # Gitleaks returns:
    # 0 = no findings
    # 1 = leaks found

    if result.returncode not in [0, 1]:

        raise Exception(
            f"Secret scan failed: {result.stderr}"
        )

    # No report file is written when nothing was found
    if not os.path.exists(output_file):
        return []

    with open(output_file, "r") as f:

        return json.load(f) or []


def summarize_secrets(scan_result):

    findings = []

    for result in scan_result:

        # The secret value itself is deliberately never copied into findings
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
            )
        })

    return findings
