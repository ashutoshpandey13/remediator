def normalize_k8s_findings(findings):

    normalized = []

    for finding in findings:

        normalized.append({
            "type": "MISCONFIG",
            "id": finding.get("id"),
            "severity": finding.get("severity"),
            "title": finding.get("title"),
            "message": finding.get("message")
        })

    return normalized


def normalize_cves(cves):

    normalized = []

    for cve in cves:

        normalized.append({
            "type": "CVE",
            "id": cve.get("cve"),
            "severity": cve.get("severity"),
            "package": cve.get("package"),
            "installed_version": cve.get("installed"),
            "fixed_version": cve.get("fixed")
        })

    return normalized


def combine_findings(
    k8s_findings,
    cve_findings
):

    return (
        normalize_k8s_findings(k8s_findings)
        +
        normalize_cves(cve_findings)
    )
