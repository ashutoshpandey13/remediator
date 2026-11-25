import subprocess
import json


def scan_code(path):

    output_file = "reports/sast_scan.json"

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
        text=True
    )

    # semgrep returns:
    # 0 = no findings
    # 1 = findings found

    if result.returncode not in [0, 1]:

        print(result.stderr)

        raise Exception(
            "Semgrep scan failed"
        )

    with open(output_file, "r") as f:
        return json.load(f)


def summarize_sast(scan_result):

    findings = []

    for result in scan_result.get(
        "results",
        []
    ):

        findings.append({

            "type": "SAST",

            "id": result.get(
                "check_id"
            ),

            "severity": result.get(
                "extra",
                {}
            ).get(
                "severity"
            ),

            "message": result.get(
                "extra",
                {}
            ).get(
                "message"
            ),

            "file": result.get(
                "path"
            )
        })

    return findings
