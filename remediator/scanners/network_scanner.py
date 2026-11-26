from remediator.scanners.feed_loader import load_feed


def scan_network():

    return load_feed("NETWORK_FINDINGS_PATH")


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
