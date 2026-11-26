from agents.feed_loader import load_feed


def scan_runtime():

    return load_feed("RUNTIME_FINDINGS_PATH")


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
