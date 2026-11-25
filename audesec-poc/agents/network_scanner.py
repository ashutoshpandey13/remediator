import json


def scan_network():

    with open(
        "reports/network_findings.json",
        "r"
    ) as f:

        return json.load(f)


def summarize_network(scan_result):

    findings = []

    for result in scan_result:

        findings.append({

            "type": "NETWORK",

            "severity": result.get(
                "severity"
            ),

            "id": result.get(
                "id"
            ),

            "message": result.get(
                "description"
            )
        })

    return findings
