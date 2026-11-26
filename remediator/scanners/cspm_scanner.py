from remediator.scanners.feed_loader import load_feed


def scan_cspm():

    return load_feed("CSPM_FINDINGS_PATH")


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
