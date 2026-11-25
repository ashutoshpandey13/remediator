import json


def scan_cspm():

    with open(
        "reports/cspm_scan.json",
        "r"
    ) as f:

        return json.load(f)


def summarize_cspm(scan_result):

    findings = []

    for result in scan_result:

        findings.append({

            "type": "CSPM",

            "id": result.get(
                "CheckID"
            ),

            "severity": result.get(
                "Severity"
            ),

            "message": result.get(
                "Description"
            ),

            "resource": result.get(
                "Resource"
            )
        })

    return findings
