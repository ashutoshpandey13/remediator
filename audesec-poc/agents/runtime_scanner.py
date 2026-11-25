import json


def scan_runtime():

    with open(
        "reports/runtime_findings.json",
        "r"
    ) as f:

        return json.load(f)


def summarize_runtime(scan_result):

    findings = []

    for result in scan_result:

        findings.append({

            "type": "RUNTIME",

            "severity": result.get(
                "priority"
            ),

            "rule": result.get(
                "rule"
            ),

            "message": result.get(
                "output"
            )
        })

    return findings
